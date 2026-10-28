#!/usr/bin/env python3
"""RFC-0003 §4 / RFC-0004 §§2,5.5,6 counterexamples; no proof consumer."""

from fractions import Fraction
from random import Random


def main():
    prime = 2**31 - 1
    for left, right, advertised in [(128, 128, 2**16), (8, 128, 2**20)]:
        maximum = (prime - 1) // (2 * left * right)
        assert maximum == advertised - 1
        assert 2 * maximum * left * right < prime
        assert 2 * advertised * left * right > prime
        bound = advertised * left * right
        recovered = bound % prime
        if 2 * recovered > prime:
            recovered -= prime
        assert bound == 2**30 and recovered == -(2**30 - 1)
        assert bound != recovered and (bound - recovered) % prime == 0

    rng = Random(26)
    for _ in range(10_000):
        left, right = rng.randrange(32_769), rng.randrange(32_769)
        dimension = rng.randrange(1, 2**20 + 1)
        bound = left * right * dimension
        assert (2 * bound < prime) == (Fraction(bound) < Fraction(prime, 2))

    # The upper inequality in §5.5 alone is not the ceiling relation.
    maximum, scale = 128, 1
    assert 127 * scale - maximum < 127
    assert scale != (maximum + 126) // 127 == 2
    for maximum in range(32_769):
        expected = (maximum + 126) // 127
        for scale in [expected - 1, expected, expected + 1]:
            assert (0 <= 127 * scale - maximum < 127) == (scale == expected)
    assert (0 + 126) // 127 == 0  # A zero row needs an explicit quantisation rule.
    print("strict M31 dimensions: int8*int8<=65535; int4*int8<=1048575")
    print("10000 static-bound and 98307 exact ceiling checks passed")
    print("advertised endpoints recover 1073741824 as -1073741823; M=128,s=1 passes upper-only scale check")


if __name__ == "__main__":
    main()
