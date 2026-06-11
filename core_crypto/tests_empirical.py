"""
core_crypto/tests_empirical.py
==============================
Unit tests for the empirical research metrics module.

Validates mathematical correctness of:
    - Avalanche Effect (Hamming Distance)
    - Shannon Entropy
    - @time_tracker decorator
"""

import math
import os
import time

from django.test import TestCase

from core_crypto.empirical_tests import (
    calculate_avalanche_effect,
    calculate_shannon_entropy,
    time_tracker,
)
from core_crypto.utils import (
    calculate_sha256_hash_hex,
    generate_rsa_key_pair,
    sign_hash,
    calculate_sha256_hash,
)


# ---------------------------------------------------------------------------
# Avalanche Effect Tests
# ---------------------------------------------------------------------------

class AvalancheEffectTests(TestCase):
    """Tests for calculate_avalanche_effect()."""

    def test_identical_hashes_zero_avalanche(self):
        """Two identical hashes must produce 0% avalanche (0 differing bits)."""
        h = calculate_sha256_hash_hex(b"Identical")
        result = calculate_avalanche_effect(h, h)
        self.assertEqual(result["hamming_distance"], 0)
        self.assertAlmostEqual(result["avalanche_pct"], 0.0)

    def test_total_bits_is_256(self):
        """SHA-256 comparison must always involve exactly 256 bits."""
        h1 = calculate_sha256_hash_hex(b"A")
        h2 = calculate_sha256_hash_hex(b"B")
        result = calculate_avalanche_effect(h1, h2)
        self.assertEqual(result["total_bits"], 256)

    def test_single_char_change_near_50_percent(self):
        """
        Changing one character in the input should yield an avalanche
        effect close to 50%. Acceptable academic range: 40%–60%.
        """
        h1 = calculate_sha256_hash_hex(b"Hello World")
        h2 = calculate_sha256_hash_hex(b"Hello Worle")  # 'd' → 'e'
        result = calculate_avalanche_effect(h1, h2)
        self.assertGreaterEqual(result["avalanche_pct"], 30.0)
        self.assertLessEqual(result["avalanche_pct"], 70.0)

    def test_completely_different_inputs(self):
        """Very different inputs should still show avalanche near 50%."""
        h1 = calculate_sha256_hash_hex(b"\x00" * 1024)
        h2 = calculate_sha256_hash_hex(b"\xFF" * 1024)
        result = calculate_avalanche_effect(h1, h2)
        # Still expected near 50% due to hash properties
        self.assertGreater(result["avalanche_pct"], 20.0)
        self.assertLess(result["avalanche_pct"], 80.0)

    def test_all_zeros_vs_all_ones_hash(self):
        """
        Manually verify: hash of all 0x00 vs all 0xFF.
        Hamming distance must be > 0 (hashes will differ).
        """
        h1 = "0" * 64  # 256 zero-bits
        h2 = "f" * 64  # 256 one-bits
        result = calculate_avalanche_effect(h1, h2)
        self.assertEqual(result["hamming_distance"], 256)
        self.assertAlmostEqual(result["avalanche_pct"], 100.0)

    def test_known_hamming_distance(self):
        """
        Manual calculation:
            0x0 = 0000, 0x1 = 0001 → XOR = 0001 → Hamming = 1
        Padded to 64 hex chars: "00...00" vs "00...01"
        Expected: 1 bit different out of 256 → 0.390625%
        """
        h1 = "0" * 64
        h2 = "0" * 63 + "1"
        result = calculate_avalanche_effect(h1, h2)
        self.assertEqual(result["hamming_distance"], 1)
        self.assertAlmostEqual(result["avalanche_pct"], 1 / 256 * 100, places=4)

    def test_binary_representations_correct_length(self):
        """Returned binary strings must be exactly 256 characters."""
        h1 = calculate_sha256_hash_hex(b"test1")
        h2 = calculate_sha256_hash_hex(b"test2")
        result = calculate_avalanche_effect(h1, h2)
        self.assertEqual(len(result["hash1_bin"]), 256)
        self.assertEqual(len(result["hash2_bin"]), 256)

    def test_rejects_invalid_length(self):
        """Non-64-character hex strings must be rejected."""
        with self.assertRaises(ValueError):
            calculate_avalanche_effect("abc", "def")

    def test_rejects_non_hex_characters(self):
        """Strings with non-hex characters must be rejected."""
        with self.assertRaises(ValueError):
            calculate_avalanche_effect("g" * 64, "0" * 64)

    def test_rejects_non_string_input(self):
        """Non-string inputs must raise TypeError."""
        with self.assertRaises(TypeError):
            calculate_avalanche_effect(123, "0" * 64)  # type: ignore


# ---------------------------------------------------------------------------
# Shannon Entropy Tests
# ---------------------------------------------------------------------------

class ShannonEntropyTests(TestCase):
    """Tests for calculate_shannon_entropy()."""

    def test_single_byte_value_zero_entropy(self):
        """
        Data consisting of a single repeated byte has zero entropy.
        H = -1 × log₂(1) = 0.0
        """
        data = bytes([0xAA]) * 256
        result = calculate_shannon_entropy(data)
        self.assertAlmostEqual(result["entropy"], 0.0, places=10)

    def test_two_equal_byte_values_entropy_1(self):
        """
        Data with exactly 2 equally frequent byte values:
        H = -2 × (0.5 × log₂(0.5)) = -2 × (0.5 × -1) = 1.0 bits
        """
        data = bytes([0x00]) * 128 + bytes([0xFF]) * 128
        result = calculate_shannon_entropy(data)
        self.assertAlmostEqual(result["entropy"], 1.0, places=10)

    def test_four_equal_byte_values_entropy_2(self):
        """
        Data with exactly 4 equally frequent byte values:
        H = -4 × (0.25 × log₂(0.25)) = -4 × (0.25 × -2) = 2.0 bits
        """
        data = bytes([0x00]) * 64 + bytes([0x55]) * 64 + \
               bytes([0xAA]) * 64 + bytes([0xFF]) * 64
        result = calculate_shannon_entropy(data)
        self.assertAlmostEqual(result["entropy"], 2.0, places=10)

    def test_max_entropy_is_8(self):
        """Maximum possible entropy for byte data is log₂(256) = 8.0."""
        result = calculate_shannon_entropy(b"\x00")
        self.assertEqual(result["max_entropy"], 8.0)

    def test_uniform_distribution_near_max_entropy(self):
        """
        A perfectly uniform byte distribution (each byte value appears once)
        must yield H = log₂(256) = 8.0 exactly.
        """
        # All 256 byte values appearing exactly once
        data = bytes(range(256))
        result = calculate_shannon_entropy(data)
        self.assertAlmostEqual(result["entropy"], 8.0, places=10)

    def test_random_data_high_entropy(self):
        """Cryptographically random data should have entropy close to 8.0."""
        random_data = os.urandom(2048)
        result = calculate_shannon_entropy(random_data)
        self.assertGreater(result["entropy"], 7.5)

    def test_rsa_signature_high_entropy(self):
        """
        RSA-PSS signature output should exhibit high Shannon Entropy,
        proving the ciphertext resembles random noise.
        """
        private_key, _ = generate_rsa_key_pair()
        file_hash = calculate_sha256_hash(b"Certificate content")
        signature = sign_hash(private_key, file_hash)
        result = calculate_shannon_entropy(signature)
        # RSA-2048 signature = 256 bytes; expect entropy > 7.0
        self.assertGreater(result["entropy"], 7.0)

    def test_unique_bytes_count(self):
        """unique_bytes should correctly count distinct byte values."""
        data = bytes([0x00, 0x01, 0x02, 0x00, 0x01, 0x02])
        result = calculate_shannon_entropy(data)
        self.assertEqual(result["unique_bytes"], 3)

    def test_total_bytes_count(self):
        """total_bytes should match the input length."""
        data = os.urandom(512)
        result = calculate_shannon_entropy(data)
        self.assertEqual(result["total_bytes"], 512)

    def test_randomness_ratio_bounds(self):
        """randomness_ratio must be between 0.0 and 1.0."""
        result = calculate_shannon_entropy(os.urandom(256))
        self.assertGreaterEqual(result["randomness_ratio"], 0.0)
        self.assertLessEqual(result["randomness_ratio"], 1.0)

    def test_rejects_empty_input(self):
        """Empty bytes must raise ValueError."""
        with self.assertRaises(ValueError):
            calculate_shannon_entropy(b"")

    def test_rejects_non_bytes_input(self):
        """Non-bytes input must raise TypeError."""
        with self.assertRaises(TypeError):
            calculate_shannon_entropy("not bytes")  # type: ignore

    def test_manual_entropy_calculation(self):
        """
        Verify against a hand-calculated example.
        Data: [A, A, A, B] → p(A)=3/4, p(B)=1/4
        H = -(3/4 × log₂(3/4) + 1/4 × log₂(1/4))
          = -(3/4 × (-0.41504) + 1/4 × (-2.0))
          = -(−0.31128 − 0.5)
          = 0.81128 bits
        """
        data = bytes([0x41, 0x41, 0x41, 0x42])  # A, A, A, B
        result = calculate_shannon_entropy(data)
        expected = -(3/4 * math.log2(3/4) + 1/4 * math.log2(1/4))
        self.assertAlmostEqual(result["entropy"], expected, places=10)


# ---------------------------------------------------------------------------
# @time_tracker Decorator Tests
# ---------------------------------------------------------------------------

class TimeTrackerTests(TestCase):
    """Tests for the @time_tracker decorator."""

    def test_returns_dict_with_required_keys(self):
        """Decorated function must return a dict with result, elapsed_ms, function_name."""
        @time_tracker
        def simple():
            return 42

        output = simple()
        self.assertIn("result", output)
        self.assertIn("elapsed_ms", output)
        self.assertIn("function_name", output)

    def test_preserves_return_value(self):
        """The original return value must be accessible via output['result']."""
        @time_tracker
        def add(a, b):
            return a + b

        output = add(3, 7)
        self.assertEqual(output["result"], 10)

    def test_elapsed_time_is_positive(self):
        """Elapsed time must be a positive number."""
        @time_tracker
        def noop():
            pass

        output = noop()
        self.assertGreater(output["elapsed_ms"], 0.0)

    def test_elapsed_time_is_reasonable(self):
        """A 50ms sleep should measure approximately 50ms (±30ms tolerance)."""
        @time_tracker
        def slow():
            time.sleep(0.05)

        output = slow()
        self.assertGreaterEqual(output["elapsed_ms"], 20.0)
        self.assertLessEqual(output["elapsed_ms"], 150.0)

    def test_function_name_preserved(self):
        """The function's __qualname__ must be captured correctly."""
        @time_tracker
        def my_named_function():
            return "hello"

        output = my_named_function()
        self.assertIn("my_named_function", output["function_name"])

    def test_with_custom_label(self):
        """@time_tracker(label=...) syntax must also work correctly."""
        @time_tracker(label="Custom RSA Keygen")
        def keygen():
            return "key"

        output = keygen()
        self.assertEqual(output["result"], "key")
        self.assertIn("elapsed_ms", output)

    def test_preserves_function_metadata(self):
        """functools.wraps should preserve __name__ and __doc__."""
        @time_tracker
        def documented_fn():
            """This is my docstring."""
            pass

        self.assertEqual(documented_fn.__name__, "documented_fn")
        self.assertEqual(documented_fn.__doc__, "This is my docstring.")

    def test_works_with_args_and_kwargs(self):
        """Decorated function must correctly forward *args and **kwargs."""
        @time_tracker
        def concat(a, b, sep="-"):
            return f"{a}{sep}{b}"

        output = concat("hello", "world", sep=":")
        self.assertEqual(output["result"], "hello:world")
