"""
core_crypto/serializers.py
==========================
DRF Serializers for validating API request payloads.

Each serializer enforces strict input validation before the request
reaches the cryptographic processing layer.
"""

import base64

from rest_framework import serializers


class GenerateKeysSerializer(serializers.Serializer):
    """
    POST /api/generate-keys/

    No input fields required — the server generates a fresh key pair.
    This serializer exists for consistency and future extensibility
    (e.g., adding key size options).
    """
    pass


class SignCertificateSerializer(serializers.Serializer):
    """
    POST /api/sign-certificate/

    Expects:
        - image:       The certificate image file (multipart upload).
        - private_key: The RSA Private Key in PEM format (text field).
    """
    image = serializers.FileField(
        help_text="Certificate image file to sign (any image format).",
        required=True,
    )
    private_key = serializers.CharField(
        help_text="RSA Private Key in PEM format (-----BEGIN PRIVATE KEY-----).",
        required=True,
        trim_whitespace=False,  # PEM format is whitespace-sensitive
    )

    def validate_image(self, value):
        """Reject empty files."""
        if value.size == 0:
            raise serializers.ValidationError("Uploaded file is empty.")
        # Cap at 10MB to prevent abuse
        max_size = 10 * 1024 * 1024
        if value.size > max_size:
            raise serializers.ValidationError(
                f"File too large ({value.size} bytes). Maximum is {max_size} bytes (10MB)."
            )
        return value

    def validate_private_key(self, value):
        """Verify the PEM string looks like a valid private key header."""
        stripped = value.strip()
        if not (
            stripped.startswith("-----BEGIN PRIVATE KEY-----")
            or stripped.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            or stripped.startswith("-----BEGIN RSA PRIVATE KEY-----")
        ):
            raise serializers.ValidationError(
                "Invalid PEM format. The private key must start with "
                "'-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----'."
            )
        return stripped


class VerifyCertificateSerializer(serializers.Serializer):
    """
    POST /api/verify-certificate/

    Expects:
        - image:         The certificate image file to verify (multipart upload).
        - signature:     The RSA digital signature, base64-encoded.
        - public_key:    The RSA Public Key in PEM format (text field).
        - original_hash: (Optional) The original SHA-256 hex hash from signing.
                         If provided, the Avalanche Effect is computed between
                         this hash and the current file's hash.
    """
    image = serializers.FileField(
        help_text="Certificate image file to verify.",
        required=True,
    )
    signature = serializers.CharField(
        help_text="RSA-PSS digital signature, base64-encoded.",
        required=True,
        trim_whitespace=True,
    )
    public_key = serializers.CharField(
        help_text="RSA Public Key in PEM format (-----BEGIN PUBLIC KEY-----).",
        required=True,
        trim_whitespace=False,
    )
    original_hash = serializers.CharField(
        help_text=(
            "Optional. The original SHA-256 hex hash returned during signing. "
            "Used to compute the Avalanche Effect for tamper analysis."
        ),
        required=False,
        default=None,
        allow_blank=True,
    )

    def validate_signature(self, value):
        """Verify the signature is valid base64."""
        try:
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) == 0:
                raise serializers.ValidationError("Decoded signature is empty.")
        except Exception as e:
            raise serializers.ValidationError(
                f"Invalid base64 encoding for signature: {e}"
            )
        return value

    def validate_public_key(self, value):
        """Verify the PEM string looks like a valid public key header."""
        stripped = value.strip()
        if not stripped.startswith("-----BEGIN PUBLIC KEY-----"):
            raise serializers.ValidationError(
                "Invalid PEM format. The public key must start with "
                "'-----BEGIN PUBLIC KEY-----'."
            )
        return stripped

    def validate_original_hash(self, value):
        """If provided, validate it's a proper 64-char hex string."""
        if value is None or value == "":
            return None
        if len(value) != 64:
            raise serializers.ValidationError(
                f"original_hash must be exactly 64 hex characters (SHA-256), "
                f"got {len(value)}."
            )
        try:
            int(value, 16)
        except ValueError:
            raise serializers.ValidationError(
                "original_hash contains non-hexadecimal characters."
            )
        return value

    def validate_image(self, value):
        """Reject empty files."""
        if value.size == 0:
            raise serializers.ValidationError("Uploaded file is empty.")
        max_size = 10 * 1024 * 1024
        if value.size > max_size:
            raise serializers.ValidationError(
                f"File too large ({value.size} bytes). Maximum is {max_size} bytes (10MB)."
            )
        return value

from core_crypto.models import VerificationHistory

class VerificationHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VerificationHistory
        fields = '__all__'
