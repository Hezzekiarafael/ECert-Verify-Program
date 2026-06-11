"""
core_crypto/views.py
====================
Django REST Framework API views for the E-Certificate Verification System.

Endpoints:
    POST /api/generate-keys/       — Generate RSA-2048 key pair.
    POST /api/sign-certificate/    — Hash + sign a certificate image.
    POST /api/verify-certificate/  — Verify a certificate's digital signature.

Each endpoint delegates core processing to a @time_tracker-decorated function
so that execution time (in milliseconds) is captured and returned in every
API response for academic benchmarking.
"""

import base64
import logging
import time


from rest_framework import status
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

from core_crypto.empirical_tests import (
    calculate_avalanche_effect,
    calculate_shannon_entropy,
    time_tracker,
)
from core_crypto.serializers import (
    GenerateKeysSerializer,
    SignCertificateSerializer,
    VerifyCertificateSerializer,
    VerificationHistorySerializer,
)
from core_crypto.models import VerificationHistory
from core_crypto.utils import (
    generate_rsa_key_pair,
    serialize_private_key,
    serialize_public_key,
    load_private_key,
    load_public_key,
    calculate_sha256_hash,
    calculate_sha256_hash_hex,
    sign_hash,
    verify_signature,
    convert_pdf_to_png_bytes,
    normalize_image,
)

logger = logging.getLogger(__name__)


# ==========================================================================
# 1. POST /api/generate-keys/
# ==========================================================================

# Core processing logic — decorated with @time_tracker for benchmarking.
@time_tracker(label="generate_keys")
def _process_generate_keys():
    """
    Generate an RSA-2048 key pair and serialize both keys to PEM format.
    Wrapped with @time_tracker to measure key generation performance.
    """
    private_key, public_key = generate_rsa_key_pair()

    private_pem = serialize_private_key(private_key).decode('utf-8')
    public_pem = serialize_public_key(public_key).decode('utf-8')

    return {
        "private_key": private_pem,
        "public_key": public_pem,
        "key_size_bits": 2048,
        "algorithm": "RSA",
    }


@api_view(['POST'])
def generate_keys_view(request):
    """
    POST /api/generate-keys/

    Generates a fresh RSA-2048 key pair.

    Request:  No body required (empty POST).
    Response:
        {
            "status": "success",
            "data": {
                "private_key": "-----BEGIN PRIVATE KEY-----\n...",
                "public_key":  "-----BEGIN PUBLIC KEY-----\n...",
                "key_size_bits": 2048,
                "algorithm": "RSA"
            },
            "execution_time_ms": 123.4567
        }
    """
    serializer = GenerateKeysSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    try:
        tracked = _process_generate_keys()

        return Response({
            "status": "success",
            "data": tracked["result"],
            "execution_time_ms": round(tracked["elapsed_ms"], 4),
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception("Key generation failed")
        return Response({
            "status": "error",
            "message": f"Key generation failed: {str(e)}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==========================================================================
# 2. POST /api/sign-certificate/
# ==========================================================================

@time_tracker(label="sign_certificate")
def _process_sign_certificate(file_bytes: bytes, private_key_pem: str):
    """
    Hash the certificate image, sign the hash, and compute entropy metrics.
    Wrapped with @time_tracker to measure the full signing pipeline.

    Pipeline:
        1. SHA-256 hash of the image bytes.
        2. RSA-PSS sign the hash with the private key.
        3. Shannon Entropy analysis of the signature.
    """
    # Step 1: Load the private key from PEM
    private_key = load_private_key(private_key_pem.encode('utf-8'))

    # Step 2: Hash the certificate image
    start_hash = time.perf_counter()
    file_hash_bytes = calculate_sha256_hash(file_bytes)
    file_hash_hex = calculate_sha256_hash_hex(file_bytes)
    hashing_time_ms = (time.perf_counter() - start_hash) * 1000.0

    # Step 3: Sign the hash with RSA-PSS
    signature_bytes = sign_hash(private_key, file_hash_bytes)

    # Step 4: Base64-encode the signature for safe JSON transport
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    # Step 5: Compute Shannon Entropy of the signature
    entropy_result = calculate_shannon_entropy(signature_bytes)

    return {
        "sha256_hash": file_hash_hex,
        "hashing_time_ms": round(hashing_time_ms, 4),
        "digital_signature_b64": signature_b64,
        "signature_size_bytes": len(signature_bytes),
        "signing_algorithm": "RSA-PSS (SHA-256, MGF1-SHA256, MAX_SALT)",
        "entropy_analysis": {
            "entropy_bits": round(entropy_result["entropy"], 6),
            "max_entropy_bits": entropy_result["max_entropy"],
            "randomness_ratio": round(entropy_result["randomness_ratio"], 6),
            "unique_byte_values": entropy_result["unique_bytes"],
            "total_bytes_analyzed": entropy_result["total_bytes"],
        },
    }


@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def sign_certificate_view(request):
    """
    POST /api/sign-certificate/

    Accepts a certificate image and a private key, then returns the
    SHA-256 hash, RSA-PSS digital signature (base64), and entropy analysis.

    Request (multipart/form-data):
        - image:       Certificate image file.
        - private_key: RSA Private Key in PEM format (text).

    Response:
        {
            "status": "success",
            "data": {
                "sha256_hash": "a1b2c3...",
                "digital_signature_b64": "BASE64...",
                "signature_size_bytes": 256,
                "signing_algorithm": "RSA-PSS ...",
                "entropy_analysis": {
                    "entropy_bits": 7.1234,
                    "max_entropy_bits": 8.0,
                    "randomness_ratio": 0.8904,
                    "unique_byte_values": 190,
                    "total_bytes_analyzed": 256
                }
            },
            "execution_time_ms": 45.6789
        }
    """
    serializer = SignCertificateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    try:
        # Read the uploaded image as raw bytes
        image_file = serializer.validated_data['image']
        file_bytes = image_file.read()

        private_key_pem = serializer.validated_data['private_key']

        # Feature: Standardized Image Normalization
        # We normalize EVERYTHING (PDF or Image) to a standard pixel matrix
        # (Grayscale, 2480x3508px) to support the "Citra Digital" title.
        start_norm = time.perf_counter()
        if image_file.name.lower().endswith('.pdf') or image_file.content_type == 'application/pdf':
            file_bytes = convert_pdf_to_png_bytes(file_bytes)
        else:
            # It's an image (JPG/PNG), normalize it directly
            file_bytes = normalize_image(file_bytes)
        normalization_time_ms = (time.perf_counter() - start_norm) * 1000.0

        # Execute the tracked processing pipeline
        tracked = _process_sign_certificate(file_bytes, private_key_pem)

        # Include normalized image for download
        import base64 as b64_module
        normalized_image_b64 = b64_module.b64encode(file_bytes).decode('utf-8')

        response_data = tracked["result"]
        response_data["normalization_time_ms"] = round(normalization_time_ms, 4)
        response_data["normalized_image_b64"] = normalized_image_b64

        return Response({
            "status": "success",
            "data": response_data,
            "execution_time_ms": round(tracked["elapsed_ms"], 4),
        }, status=status.HTTP_200_OK)

    except ValueError as e:
        return Response({
            "status": "error",
            "message": f"Cryptographic error: {str(e)}",
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.exception("Certificate signing failed")
        return Response({
            "status": "error",
            "message": f"Signing failed: {str(e)}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ==========================================================================
# 3. POST /api/verify-certificate/
# ==========================================================================

@time_tracker(label="verify_certificate")
def _process_verify_certificate(
    file_bytes: bytes,
    signature_b64: str,
    public_key_pem: str,
    original_hash_hex: str = None,
):
    """
    Verify a certificate's digital signature and compute tamper analysis.
    Wrapped with @time_tracker to measure the full verification pipeline.

    Pipeline:
        1. SHA-256 hash of the uploaded image.
        2. Decode the base64 signature.
        3. RSA-PSS verify the signature against the hash.
        4. If original_hash is provided, compute Avalanche Effect.
    """
    # Step 1: Load the public key
    public_key = load_public_key(public_key_pem.encode('utf-8'))

    # Step 2: Hash the uploaded certificate image
    file_hash_bytes = calculate_sha256_hash(file_bytes)
    current_hash_hex = calculate_sha256_hash_hex(file_bytes)

    # Step 3: Decode the base64-encoded signature
    signature_bytes = base64.b64decode(signature_b64)

    # Step 4: Verify the signature using RSA-PSS
    is_valid = verify_signature(public_key, file_hash_bytes, signature_bytes)

    result = {
        "is_valid": is_valid,
        "verification_algorithm": "RSA-PSS (SHA-256, MGF1-SHA256, MAX_SALT)",
        "current_hash": current_hash_hex,
        "message": (
            "AUTHENTIC — The certificate is valid and untampered."
            if is_valid else
            "INVALID — The certificate has been tampered with or the "
            "signature/key is incorrect."
        ),
    }

    # Step 5: Avalanche Effect analysis (if original hash is provided)
    if original_hash_hex:
        try:
            avalanche = calculate_avalanche_effect(original_hash_hex, current_hash_hex)
            result["avalanche_analysis"] = {
                "original_hash": original_hash_hex,
                "current_hash": current_hash_hex,
                "total_bits_compared": avalanche["total_bits"],
                "differing_bits": avalanche["hamming_distance"],
                "avalanche_effect_pct": round(avalanche["avalanche_pct"], 4),
                "hashes_match": original_hash_hex == current_hash_hex,
            }
        except (ValueError, TypeError) as e:
            result["avalanche_analysis"] = {
                "error": f"Could not compute avalanche effect: {str(e)}",
            }
    else:
        result["avalanche_analysis"] = {
            "note": (
                "No original_hash provided. Submit the SHA-256 hash from the "
                "signing response to enable Avalanche Effect analysis."
            ),
        }

    return result


@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def verify_certificate_view(request):
    """
    POST /api/verify-certificate/

    Accepts a certificate image, its digital signature, and the public key.
    Returns whether the certificate is authentic, plus Avalanche Effect
    analysis if the original hash is provided.

    Request (multipart/form-data):
        - image:         Certificate image file.
        - signature:     RSA-PSS signature, base64-encoded.
        - public_key:    RSA Public Key in PEM format (text).
        - original_hash: (Optional) SHA-256 hex hash from signing response.

    Response:
        {
            "status": "success",
            "data": {
                "is_valid": true,
                "verification_algorithm": "RSA-PSS ...",
                "current_hash": "a1b2c3...",
                "message": "AUTHENTIC — ...",
                "avalanche_analysis": {
                    "original_hash": "a1b2c3...",
                    "current_hash": "a1b2c3...",
                    "total_bits_compared": 256,
                    "differing_bits": 0,
                    "avalanche_effect_pct": 0.0,
                    "hashes_match": true
                }
            },
            "execution_time_ms": 12.3456
        }
    """
    serializer = VerifyCertificateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    try:
        # Read the uploaded image as raw bytes
        image_file = serializer.validated_data['image']
        file_bytes = image_file.read()

        signature_b64 = serializer.validated_data['signature']
        public_key_pem = serializer.validated_data['public_key']
        original_hash = serializer.validated_data.get('original_hash')

        # Feature: Standardized Image Normalization (Verification)
        # Apply the same Grayscale + Resize normalization to all formats.
        if image_file.name.lower().endswith('.pdf') or image_file.content_type == 'application/pdf':
            file_bytes = convert_pdf_to_png_bytes(file_bytes)
        else:
            file_bytes = normalize_image(file_bytes)

        # Execute the tracked verification pipeline
        tracked = _process_verify_certificate(
            file_bytes, signature_b64, public_key_pem, original_hash,
        )

        return Response({
            "status": "success",
            "data": tracked["result"],
            "execution_time_ms": round(tracked["elapsed_ms"], 4),
        }, status=status.HTTP_200_OK)

    except ValueError as e:
        return Response({
            "status": "error",
            "message": f"Cryptographic error: {str(e)}",
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.exception("Certificate verification failed")
        return Response({
            "status": "error",
            "message": f"Verification failed: {str(e)}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ==========================================================================
# 4. GET & POST /api/history/
# ==========================================================================

@api_view(['GET', 'POST'])
def history_view(request):
    """
    GET /api/history/
    POST /api/history/
    """
    if request.method == 'GET':
        history = VerificationHistory.objects.all()
        serializer = VerificationHistorySerializer(history, many=True)
        return Response({
            "status": "success",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    
    elif request.method == 'POST':
        serializer = VerificationHistorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "status": "success",
                "data": serializer.data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "status": "error",
            "message": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

