"""
core_crypto/utils.py
====================
Core cryptographic utility functions for the E-Certificate Verification System.

This module provides four essential operations:
    1. RSA-2048 Key Pair Generation
    2. SHA-256 Hash Calculation (for binary file content)
    3. Digital Signature Creation (RSA-PSS)
    4. Digital Signature Verification (RSA-PSS)

Security Notes:
    - Uses RSA-2048 as the minimum secure key size for academic/production use.
    - Uses PSS (Probabilistic Signature Scheme) padding, which is the modern,
      provably-secure padding scheme for RSA signatures. PKCS#1 v1.5 is NOT used.
    - Uses SHA-256 as the hash algorithm throughout for consistency.

Library: `cryptography` (pyca/cryptography) — the recommended Python crypto library.
"""

import hashlib
import io
from typing import Tuple

from pdf2image import convert_from_bytes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils


# ---------------------------------------------------------------------------
# 1. RSA-2048 Key Pair Generation
# ---------------------------------------------------------------------------

def generate_rsa_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA-2048 bit key pair.

    Returns:
        A tuple of (private_key, public_key) objects.

    The keys are returned as cryptography library key objects.
    To serialize them (e.g., for storage), use the helper functions
    `serialize_private_key()` and `serialize_public_key()` below.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard public exponent (Fermat number F4)
        key_size=2048,          # RSA-2048 — NIST-recommended minimum
    )
    public_key = private_key.public_key()

    return private_key, public_key


def serialize_private_key(private_key: rsa.RSAPrivateKey, passphrase: bytes = None) -> bytes:
    """
    Serialize an RSA private key to PEM format.

    Args:
        private_key: The RSA private key object.
        passphrase:  Optional passphrase to encrypt the private key at rest.
                     If None, the key is stored unencrypted (dev-only).

    Returns:
        PEM-encoded private key as bytes.
    """
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Serialize an RSA public key to PEM format.

    Args:
        public_key: The RSA public key object.

    Returns:
        PEM-encoded public key as bytes.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: bytes, passphrase: bytes = None) -> rsa.RSAPrivateKey:
    """
    Deserialize a PEM-encoded RSA private key.

    Args:
        pem_data:   PEM-encoded private key bytes.
        passphrase: Passphrase if the key was encrypted.

    Returns:
        RSA private key object.
    """
    return serialization.load_pem_private_key(pem_data, password=passphrase)


def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """
    Deserialize a PEM-encoded RSA public key.

    Args:
        pem_data: PEM-encoded public key bytes.

    Returns:
        RSA public key object.
    """
    return serialization.load_pem_public_key(pem_data)


# ---------------------------------------------------------------------------
# 2. SHA-256 Hash Calculation
# ---------------------------------------------------------------------------

def calculate_sha256_hash(file_bytes: bytes) -> bytes:
    """
    Calculate the SHA-256 digest of raw file content (bytes).

    This function is designed to hash the binary content of an uploaded
    certificate image. In a Django view, you would read the uploaded file
    and pass its bytes here:

        file_bytes = uploaded_file.read()
        digest = calculate_sha256_hash(file_bytes)

    Args:
        file_bytes: The raw binary content of the file to hash.

    Returns:
        The SHA-256 digest as raw bytes (32 bytes).

    Raises:
        TypeError: If file_bytes is not of type `bytes`.
    """
    if not isinstance(file_bytes, bytes):
        raise TypeError(
            f"Expected bytes, got {type(file_bytes).__name__}. "
            "Read the file in binary mode before hashing."
        )

    return hashlib.sha256(file_bytes).digest()


def calculate_sha256_hash_hex(file_bytes: bytes) -> str:
    """
    Calculate the SHA-256 digest and return it as a hexadecimal string.

    Convenience wrapper around `calculate_sha256_hash()` for cases where
    you need the human-readable hex representation (e.g., for display or
    database storage).

    Args:
        file_bytes: The raw binary content of the file to hash.

    Returns:
        The SHA-256 digest as a lowercase hex string (64 characters).
    """
    return hashlib.sha256(file_bytes).hexdigest()


# ---------------------------------------------------------------------------
# 3. Digital Signature — Sign Hash with RSA Private Key (PSS Padding)
# ---------------------------------------------------------------------------

def sign_hash(private_key: rsa.RSAPrivateKey, file_hash: bytes) -> bytes:
    """
    Sign a pre-computed SHA-256 hash using the RSA private key with PSS padding.

    CRITICAL SECURITY NOTE:
        This uses PSS (Probabilistic Signature Scheme) padding — the modern,
        provably-secure scheme. PKCS#1 v1.5 signing is intentionally NOT used
        due to known theoretical vulnerabilities (Bleichenbacher-style attacks).

    The function uses `Prehashed` because we receive an already-computed hash
    digest, not raw data. This is the correct pattern when the hashing step
    is separated from the signing step.

    Args:
        private_key: RSA private key used for signing.
        file_hash:   SHA-256 digest of the file (32 bytes, raw bytes).

    Returns:
        The digital signature as raw bytes.

    Raises:
        ValueError: If the hash is not the expected 32-byte SHA-256 digest.
    """
    if len(file_hash) != 32:
        raise ValueError(
            f"Expected a 32-byte SHA-256 digest, got {len(file_hash)} bytes. "
            "Use calculate_sha256_hash() to produce the correct digest."
        )

    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),      # Mask Generation Function
            salt_length=padding.PSS.MAX_LENGTH,      # Maximum salt for security
        ),
        utils.Prehashed(hashes.SHA256()),            # We're signing a pre-hashed digest
    )

    return signature


# ---------------------------------------------------------------------------
# 4. Digital Signature — Verify Signature with RSA Public Key (PSS Padding)
# ---------------------------------------------------------------------------

def verify_signature(
    public_key: rsa.RSAPublicKey,
    file_hash: bytes,
    signature: bytes,
) -> bool:
    """
    Verify a digital signature against a SHA-256 hash using the RSA public key.

    Uses PSS padding (matching the signing function) to verify that:
        1. The signature was created by the holder of the corresponding private key.
        2. The file content has not been tampered with since signing.

    Args:
        public_key: RSA public key corresponding to the private key that signed.
        file_hash:  SHA-256 digest of the file to verify (32 bytes, raw bytes).
        signature:  The digital signature bytes to verify.

    Returns:
        True  — if the signature is valid (authentic and untampered).
        False — if the signature is invalid (forged or data was modified).
    """
    try:
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        return True

    except Exception:
        # InvalidSignature is the expected exception for bad signatures,
        # but we catch broadly to ensure we never raise on verification failure.
        return False


# ---------------------------------------------------------------------------
# 5. PDF Conversion (for consistent hashing)
# ---------------------------------------------------------------------------

def convert_pdf_to_png_bytes(pdf_bytes: bytes, dpi: int = 300) -> bytes:
    """
    Convert the first page of a PDF file to a PNG image (bytes).
    This ensures consistent hashing for PDF certificates.

    Args:
        pdf_bytes: Raw bytes of the PDF file.
        dpi: Dots per inch for the conversion (default 300).

    Returns:
        Raw bytes of the PNG image.
    """
def normalize_image(image_bytes: bytes) -> bytes:
    """
    Standardizes any image (JPG, PNG, or converted PDF) into a 
    canonical digital matrix: Grayscale, 300 DPI, aspect-ratio preserved.
    
    - Portrait images are scaled to fit within 2480x3508.
    - Landscape images are scaled to fit within 3508x2480.
    The aspect ratio is always preserved to avoid distortion.
    """
    from PIL import Image
    img = Image.open(io.BytesIO(image_bytes))
    
    # 1. Convert to Grayscale (luminance only)
    img = img.convert('L')
    
    # 2. Determine orientation and compute target size preserving aspect ratio
    w, h = img.size
    if w > h:
        # Landscape orientation
        max_w, max_h = 3508, 2480
    else:
        # Portrait orientation
        max_w, max_h = 2480, 3508
    
    # Scale proportionally to fit within the max boundary
    ratio = min(max_w / w, max_h / h)
    new_w = int(w * ratio)
    new_h = int(h * ratio)
    img = img.resize((new_w, new_h), resample=Image.LANCZOS)
    
    # 3. Export to PNG bytes
    output = io.BytesIO()
    img.save(output, format='PNG')
    return output.getvalue()

def convert_pdf_to_png_bytes(pdf_bytes: bytes, dpi: int = 300) -> bytes:
    """
    Extracts the first page of a PDF and normalizes it.
    """
    try:
        poppler_path = None
        possible_paths = [
            r"C:\poppler\Release-26.02.0-0\poppler-26.02.0\Library\bin",
            r"C:\poppler\Library\bin",
            r"C:\poppler\bin"
        ]
        import os
        for p in possible_paths:
            if os.path.exists(p):
                poppler_path = p
                break

        images = convert_from_bytes(pdf_bytes, first_page=1, last_page=1, dpi=dpi, poppler_path=poppler_path)
        
        if not images:
            raise ValueError("Could not extract any pages from the PDF.")

        # Convert the extracted PIL image to bytes first
        img_byte_arr = io.BytesIO()
        images[0].save(img_byte_arr, format='PNG')
        
        # Then normalize it
        return normalize_image(img_byte_arr.getvalue())
        
    except Exception as e:
        raise ValueError(f"PDF/Image processing failed: {str(e)}")

