"""
core_crypto/tests.py
====================
Unit tests for the core cryptographic utility functions.

These tests validate the full certificate signing & verification workflow:
    1. Key pair generation produces valid RSA-2048 keys.
    2. SHA-256 hashing produces consistent, correct-length digests.
    3. Signing a hash with the private key produces a valid signature.
    4. Verification succeeds with valid data and fails with tampered data.
    5. Key serialization/deserialization round-trips correctly.
"""

from django.test import TestCase

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
)


class RSAKeyPairGenerationTests(TestCase):
    """Tests for RSA-2048 key pair generation."""

    def test_generate_key_pair_returns_tuple(self):
        """Key generation should return a (private, public) tuple."""
        private_key, public_key = generate_rsa_key_pair()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

    def test_key_size_is_2048(self):
        """Generated private key must be exactly 2048 bits."""
        private_key, _ = generate_rsa_key_pair()
        self.assertEqual(private_key.key_size, 2048)

    def test_public_exponent_is_65537(self):
        """Public exponent must be the standard F4 value (65537)."""
        private_key, public_key = generate_rsa_key_pair()
        self.assertEqual(public_key.public_numbers().e, 65537)


class KeySerializationTests(TestCase):
    """Tests for key serialization and deserialization."""

    def setUp(self):
        self.private_key, self.public_key = generate_rsa_key_pair()

    def test_serialize_private_key_pem_format(self):
        """Serialized private key should be valid PEM."""
        pem = serialize_private_key(self.private_key)
        self.assertTrue(pem.startswith(b"-----BEGIN PRIVATE KEY-----"))

    def test_serialize_public_key_pem_format(self):
        """Serialized public key should be valid PEM."""
        pem = serialize_public_key(self.public_key)
        self.assertTrue(pem.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_private_key_roundtrip(self):
        """Private key should survive serialize → deserialize."""
        pem = serialize_private_key(self.private_key)
        loaded = load_private_key(pem)
        # Verify they produce the same serialized output
        self.assertEqual(serialize_private_key(loaded), pem)

    def test_public_key_roundtrip(self):
        """Public key should survive serialize → deserialize."""
        pem = serialize_public_key(self.public_key)
        loaded = load_public_key(pem)
        self.assertEqual(serialize_public_key(loaded), pem)

    def test_encrypted_private_key_roundtrip(self):
        """Private key encrypted with passphrase should roundtrip."""
        passphrase = b"s3cur3_p@ss!"
        pem = serialize_private_key(self.private_key, passphrase=passphrase)
        self.assertTrue(pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        loaded = load_private_key(pem, passphrase=passphrase)
        # Compare by re-serializing without encryption
        self.assertEqual(
            serialize_private_key(loaded),
            serialize_private_key(self.private_key),
        )


class SHA256HashTests(TestCase):
    """Tests for SHA-256 hash calculation."""

    def test_hash_returns_32_bytes(self):
        """SHA-256 digest must be exactly 32 bytes."""
        data = b"Certificate image binary content"
        digest = calculate_sha256_hash(data)
        self.assertEqual(len(digest), 32)

    def test_hash_hex_returns_64_chars(self):
        """SHA-256 hex digest must be exactly 64 characters."""
        data = b"Certificate image binary content"
        hex_digest = calculate_sha256_hash_hex(data)
        self.assertEqual(len(hex_digest), 64)

    def test_hash_is_deterministic(self):
        """Same input must always produce the same hash."""
        data = b"Identical content"
        self.assertEqual(
            calculate_sha256_hash(data),
            calculate_sha256_hash(data),
        )

    def test_different_input_different_hash(self):
        """Different inputs must produce different hashes."""
        hash_a = calculate_sha256_hash(b"Content A")
        hash_b = calculate_sha256_hash(b"Content B")
        self.assertNotEqual(hash_a, hash_b)

    def test_type_error_on_non_bytes(self):
        """Passing a string instead of bytes should raise TypeError."""
        with self.assertRaises(TypeError):
            calculate_sha256_hash("not bytes")  # type: ignore

    def test_empty_bytes_produces_valid_hash(self):
        """Even empty bytes should produce a valid 32-byte hash."""
        digest = calculate_sha256_hash(b"")
        self.assertEqual(len(digest), 32)


class DigitalSignatureTests(TestCase):
    """Tests for the signing and verification workflow."""

    def setUp(self):
        """Generate a fresh key pair and sample hash for each test."""
        self.private_key, self.public_key = generate_rsa_key_pair()
        self.sample_data = b"Sample certificate image content for testing"
        self.file_hash = calculate_sha256_hash(self.sample_data)

    def test_sign_produces_bytes(self):
        """Signing should produce a non-empty byte string."""
        signature = sign_hash(self.private_key, self.file_hash)
        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)

    def test_signature_length_matches_key_size(self):
        """RSA-2048 signature should be exactly 256 bytes (2048 / 8)."""
        signature = sign_hash(self.private_key, self.file_hash)
        self.assertEqual(len(signature), 256)

    def test_valid_signature_verifies(self):
        """A legitimate signature must verify successfully."""
        signature = sign_hash(self.private_key, self.file_hash)
        is_valid = verify_signature(self.public_key, self.file_hash, signature)
        self.assertTrue(is_valid)

    def test_tampered_hash_fails_verification(self):
        """Modifying the hash after signing must cause verification to fail."""
        signature = sign_hash(self.private_key, self.file_hash)
        # Tamper with the hash (flip last byte)
        tampered_hash = self.file_hash[:-1] + bytes([self.file_hash[-1] ^ 0xFF])
        is_valid = verify_signature(self.public_key, tampered_hash, signature)
        self.assertFalse(is_valid)

    def test_tampered_signature_fails_verification(self):
        """Modifying the signature must cause verification to fail."""
        signature = sign_hash(self.private_key, self.file_hash)
        # Tamper with the signature (flip first byte)
        tampered_sig = bytes([signature[0] ^ 0xFF]) + signature[1:]
        is_valid = verify_signature(self.public_key, self.file_hash, tampered_sig)
        self.assertFalse(is_valid)

    def test_wrong_public_key_fails_verification(self):
        """Using a different key pair's public key must fail verification."""
        signature = sign_hash(self.private_key, self.file_hash)
        # Generate a completely different key pair
        _, wrong_public_key = generate_rsa_key_pair()
        is_valid = verify_signature(wrong_public_key, self.file_hash, signature)
        self.assertFalse(is_valid)

    def test_sign_rejects_wrong_hash_length(self):
        """Signing should reject input that is not a 32-byte SHA-256 digest."""
        with self.assertRaises(ValueError):
            sign_hash(self.private_key, b"too short")


class EndToEndWorkflowTest(TestCase):
    """
    Full end-to-end test simulating the certificate verification workflow:
        1. Institution generates RSA key pair
        2. Certificate image is hashed
        3. Hash is signed with private key
        4. Public key + signature are distributed
        5. Verifier recomputes hash and verifies signature
    """

    def test_full_certificate_workflow(self):
        """Complete sign-then-verify cycle should succeed."""
        # Step 1: Institution generates key pair
        private_key, public_key = generate_rsa_key_pair()

        # Step 2: Hash the certificate image
        certificate_image_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 1024  # Mock PNG
        file_hash = calculate_sha256_hash(certificate_image_bytes)

        # Step 3: Sign the hash with the institution's private key
        signature = sign_hash(private_key, file_hash)

        # Step 4: Serialize keys for storage/transmission
        pub_pem = serialize_public_key(public_key)
        priv_pem = serialize_private_key(private_key)

        # Step 5: Verifier loads the public key and verifies
        loaded_pub_key = load_public_key(pub_pem)
        recomputed_hash = calculate_sha256_hash(certificate_image_bytes)
        is_valid = verify_signature(loaded_pub_key, recomputed_hash, signature)

        self.assertTrue(is_valid, "Certificate signature verification failed!")

    def test_tampered_certificate_detected(self):
        """Modifying the certificate after signing must be detected."""
        private_key, public_key = generate_rsa_key_pair()

        original_image = b"\x89PNG\r\n\x1a\n" + b"\x00" * 1024
        file_hash = calculate_sha256_hash(original_image)
        signature = sign_hash(private_key, file_hash)

        # Attacker modifies the certificate image
        tampered_image = b"\x89PNG\r\n\x1a\n" + b"\xFF" * 1024
        tampered_hash = calculate_sha256_hash(tampered_image)

        # Verification with tampered content must fail
        is_valid = verify_signature(public_key, tampered_hash, signature)
        self.assertFalse(is_valid, "Tampered certificate was not detected!")
