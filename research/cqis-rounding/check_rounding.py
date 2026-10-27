"""Research-only counterexamples and proposed RFC-0004 A1 relation checks."""
from fractions import Fraction
from math import floor


def reference(t, e):
    value = Fraction(t, 1 << e)
    return (-1 if value < 0 else 1) * floor(abs(value) + Fraction(1, 2))


def check():
    assert (-1 + 1) // 2 == 0  # Existing bias-then-floor formula at -1/2.
    assert reference(-1, 1) == -1  # Named round-half-away semantics.
    assert 1 - reference(1, 1) * 2 == -1  # Not a nonnegative remainder.
    cases = 0
    for e in range(17):
        divisor = 1 << e
        bias = divisor // 2 if e else 0
        for t in range(-2048, 2049):
            q, r = divmod(abs(t) + bias, divisor)
            sign = -1 if t < 0 else 1
            assert sign * q == reference(t, e)
            assert abs(t) + bias == q * divisor + r
            assert 0 <= r < divisor
            cases += 1
    for t in [-(1 << 31) * 65535, ((1 << 31) - 1) * 65535]:
        for e in [0, 1, 31, 47, 63, 64]:
            q, r = divmod(abs(t) + ((1 << (e - 1)) if e else 0), 1 << e)
            assert (-1 if t < 0 else 1) * q == reference(t, e)
            assert 0 <= r < (1 << e)
            cases += 1
    print(f"PASS: both specification counterexamples; {cases} proposed-relation cases")


if __name__ == "__main__":
    check()
