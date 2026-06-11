"""
core_crypto/empirical_tests.py
==============================
Empirical testing utilities for academic research metrics on the
E-Certificate Verification System.

This module provides three measurement tools:

    1. Avalanche Effect   — Quantifies bit diffusion in SHA-256 hashes.
    2. Shannon Entropy    — Measures randomness/information density of ciphertext.
    3. @time_tracker      — Decorator for precise execution-time profiling (ms).

All formulas strictly follow their canonical academic definitions as cited
in the docstrings.

References:
    - Feistel, H. (1973). "Cryptography and Computer Privacy." Scientific American.
    - Shannon, C. E. (1948). "A Mathematical Theory of Communication." Bell System
      Technical Journal, 27(3), 379–423.
    - Stallings, W. (2017). "Cryptography and Network Security: Principles and
      Practice." 7th Edition. Pearson.
"""

import functools
import logging
import math
import time
from collections import Counter
from typing import Callable, Any

# Module-level logger — allows integration with Django's logging framework.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Avalanche Effect (Hamming Distance)
# ---------------------------------------------------------------------------

def calculate_avalanche_effect(hash1_hex: str, hash2_hex: str) -> dict:
    """
    Calculate the Avalanche Effect between two SHA-256 hex digest strings.

    The Avalanche Effect is a desirable property of cryptographic hash functions
    where a small change in input (even a single bit) produces a drastically
    different output. Ideally, flipping one input bit should flip ~50% of the
    output bits.

    Algorithm:
        1. Convert each hex string to its binary (bit-string) representation.
        2. XOR the two bit-strings to find differing bit positions.
        3. Count the number of 1-bits in the XOR result (= Hamming Distance).
        4. Avalanche Effect (%) = (Hamming Distance / Total Bits) × 100

    Academic Definition (Stallings, 2017):
        AE(%) = (Σ bit_differences / total_output_bits) × 100

        For an ideal hash function, AE ≈ 50% when a single input bit is flipped.

    Args:
        hash1_hex: First SHA-256 hex digest string  (64 hex characters = 256 bits).
        hash2_hex: Second SHA-256 hex digest string (64 hex characters = 256 bits).

    Returns:
        A dictionary containing:
            - total_bits        (int):   Total number of bits compared (256 for SHA-256).
            - hamming_distance  (int):   Number of differing bits between the two hashes.
            - avalanche_pct     (float): Avalanche Effect as a percentage (0.0–100.0).
            - hash1_bin         (str):   Binary representation of hash1 (for reporting).
            - hash2_bin         (str):   Binary representation of hash2 (for reporting).

    Raises:
        ValueError: If either hex string is not a valid SHA-256 digest (64 hex chars).

    Example:
        >>> from core_crypto.utils import calculate_sha256_hash_hex
        >>> h1 = calculate_sha256_hash_hex(b"Hello")
        >>> h2 = calculate_sha256_hash_hex(b"Hella")  # 1 character changed
        >>> result = calculate_avalanche_effect(h1, h2)
        >>> print(f"Avalanche Effect: {result['avalanche_pct']:.2f}%")
        Avalanche Effect: ~50.00%  (approximately)
    """
    # --- Input Validation ---
    _validate_hex_digest(hash1_hex, "hash1_hex")
    _validate_hex_digest(hash2_hex, "hash2_hex")

    # --- Step 1: Hex → Integer → Binary String (zero-padded to 256 bits) ---
    int1 = int(hash1_hex, 16)
    int2 = int(hash2_hex, 16)

    total_bits = len(hash1_hex) * 4  # Each hex digit = 4 bits → 64 × 4 = 256

    hash1_bin = format(int1, f'0{total_bits}b')
    hash2_bin = format(int2, f'0{total_bits}b')

    # --- Step 2: XOR to find differing positions ---
    xor_result = int1 ^ int2

    # --- Step 3: Hamming Distance = popcount(XOR result) ---
    # bin(n).count('1') is the standard Python popcount technique.
    hamming_distance = bin(xor_result).count('1')

    # --- Step 4: Avalanche Effect percentage ---
    avalanche_pct = (hamming_distance / total_bits) * 100.0

    return {
        "total_bits": total_bits,
        "hamming_distance": hamming_distance,
        "avalanche_pct": avalanche_pct,
        "hash1_bin": hash1_bin,
        "hash2_bin": hash2_bin,
    }


def _validate_hex_digest(hex_string: str, param_name: str) -> None:
    """
    Validate that a string is a well-formed SHA-256 hex digest.

    Args:
        hex_string: The string to validate.
        param_name: Parameter name for error messages.

    Raises:
        TypeError:  If not a string.
        ValueError: If not exactly 64 valid hexadecimal characters.
    """
    if not isinstance(hex_string, str):
        raise TypeError(
            f"'{param_name}' must be a hex string, got {type(hex_string).__name__}."
        )
    if len(hex_string) != 64:
        raise ValueError(
            f"'{param_name}' must be exactly 64 hex characters (SHA-256 digest), "
            f"got {len(hex_string)} characters."
        )
    try:
        int(hex_string, 16)
    except ValueError:
        raise ValueError(
            f"'{param_name}' contains non-hexadecimal characters."
        )


# ---------------------------------------------------------------------------
# 2. Shannon Entropy
# ---------------------------------------------------------------------------

def calculate_shannon_entropy(ciphertext_bytes: bytes) -> dict:
    """
    Calculate the Shannon Entropy (H) of a byte sequence.

    Shannon Entropy measures the average amount of information (in bits) per
    symbol in a message. For cryptographic ciphertext, high entropy indicates
    strong randomness — a critical property for secure encryption.

    Formula (Shannon, 1948):

        H(X) = -Σ p(xᵢ) × log₂(p(xᵢ))    for all symbols xᵢ where p(xᵢ) > 0

    Where:
        - X    = the set of all possible byte values (0x00–0xFF, i.e., 256 symbols)
        - p(xᵢ) = frequency of byte value xᵢ / total number of bytes
        - log₂ = logarithm base 2

    Bounds:
        - Minimum: H = 0.0 bits     (all bytes identical → zero randomness)
        - Maximum: H = 8.0 bits     (perfectly uniform distribution over 256 values)

    For RSA-2048 ciphertext (256 bytes), an entropy close to 8.0 indicates
    that the ciphertext is indistinguishable from random noise — exactly
    what we want from a secure encryption scheme.

    Args:
        ciphertext_bytes: The raw ciphertext bytes to analyze.

    Returns:
        A dictionary containing:
            - entropy          (float): Shannon Entropy value in bits (0.0–8.0).
            - max_entropy      (float): Theoretical maximum (always 8.0 for bytes).
            - total_bytes      (int):   Length of the input data.
            - unique_bytes     (int):   Number of distinct byte values observed.
            - randomness_ratio (float): entropy / max_entropy (0.0–1.0).
                                        1.0 = perfectly random.

    Raises:
        TypeError:  If input is not bytes.
        ValueError: If input is empty (entropy is undefined for empty data).

    Example:
        >>> import os
        >>> random_data = os.urandom(256)
        >>> result = calculate_shannon_entropy(random_data)
        >>> print(f"Entropy: {result['entropy']:.4f} bits")
        Entropy: ~7.80 bits  (close to ideal 8.0)
    """
    # --- Input Validation ---
    if not isinstance(ciphertext_bytes, bytes):
        raise TypeError(
            f"Expected bytes, got {type(ciphertext_bytes).__name__}. "
            "Pass raw ciphertext bytes."
        )
    if len(ciphertext_bytes) == 0:
        raise ValueError(
            "Cannot calculate entropy of empty data. "
            "Shannon Entropy is undefined for an empty sequence."
        )

    total_bytes = len(ciphertext_bytes)
    max_entropy = 8.0  # log₂(256) = 8.0 for byte-level analysis

    # --- Count frequency of each byte value ---
    byte_counts = Counter(ciphertext_bytes)
    unique_bytes = len(byte_counts)

    # --- Shannon Entropy Calculation ---
    # H(X) = -Σ p(xᵢ) × log₂(p(xᵢ))
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        # Only include terms where p > 0 (log₂(0) is undefined).
        # Since we iterate over observed counts, p is always > 0 here.
        entropy -= probability * math.log2(probability)

    # Clamp to [0.0, 8.0] to handle any floating-point edge cases.
    entropy = max(0.0, min(entropy, max_entropy))

    randomness_ratio = entropy / max_entropy

    return {
        "entropy": entropy,
        "max_entropy": max_entropy,
        "total_bytes": total_bytes,
        "unique_bytes": unique_bytes,
        "randomness_ratio": randomness_ratio,
    }


# ---------------------------------------------------------------------------
# 3. @time_tracker Decorator
# ---------------------------------------------------------------------------

def time_tracker(func: Callable = None, *, label: str = None) -> Callable:
    """
    Decorator to measure and log the execution time of any function.

    Measures wall-clock time using `time.perf_counter()` (the highest
    resolution timer available) and reports the result in milliseconds.

    Can be used in two ways:

        @time_tracker
        def my_function():
            ...

        @time_tracker(label="Custom Label")
        def my_function():
            ...

    The decorator logs timing information via Python's `logging` module
    at the INFO level, and also attaches the elapsed time as an attribute
    on the return value (when possible) for programmatic access.

    Args:
        func:  The function to wrap (auto-populated when used without arguments).
        label: Optional custom label for the log message. Defaults to the
               function's qualified name.

    Returns:
        A wrapped function that logs execution time after each call.
        The wrapper returns a dict with:
            - result       : The original function's return value.
            - elapsed_ms   : Execution time in milliseconds (float).
            - function_name: The name of the measured function.

    Example:
        >>> @time_tracker
        ... def slow_operation():
        ...     time.sleep(0.1)
        ...     return "done"
        >>> output = slow_operation()
        [TIME_TRACKER] slow_operation executed in 100.23 ms
        >>> print(output["elapsed_ms"])
        100.23
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> dict:
            fn_label = label or fn.__qualname__

            # Use perf_counter for the highest available resolution.
            start_time = time.perf_counter()

            result = fn(*args, **kwargs)

            end_time = time.perf_counter()
            elapsed_ms = (end_time - start_time) * 1000.0  # seconds → ms

            # Log via Python logging (integrates with Django's logging config).
            logger.info(
                "[TIME_TRACKER] %s executed in %.4f ms",
                fn_label, elapsed_ms,
            )
            # Also print for immediate console visibility during research.
            print(f"[TIME_TRACKER] {fn_label} executed in {elapsed_ms:.4f} ms")

            return {
                "result": result,
                "elapsed_ms": elapsed_ms,
                "function_name": fn.__qualname__,
            }

        return wrapper

    # Handle both @time_tracker and @time_tracker(label="...") syntax.
    if func is not None:
        # Called as @time_tracker (without parentheses)
        return decorator(func)
    else:
        # Called as @time_tracker(label="...") (with parentheses)
        return decorator
