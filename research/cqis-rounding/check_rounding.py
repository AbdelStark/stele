"""Research-only counterexamples and proposed RFC-0004 A1 relation checks."""
from fractions import Fraction
from math import floor


def reference(t, e):
    value = Fraction(t, 1 << e)
    return (-1 if value < 0 else 1) * floor(abs(value) + Fraction(1, 2))


def accepts_relation(acc, m, e, bits, witness):
    """Exact integer specification checker only; no field proof or certificate."""
    t, a, b, q, r, y = witness
    divisor = 1 << e
    bias = divisor // 2 if e else 0
    return (
        -(1 << 31) <= acc < (1 << 31) and 1 <= m < (1 << 16)
        and t == acc * m and b in (0, 1) and a >= 0 and q >= 0
        and (a != 0 or b == 0) and t == (1 - 2 * b) * a
        and a + bias == q * divisor + r and 0 <= r < divisor
        and y == (1 - 2 * b) * q and -(1 << (bits - 1)) <= y < (1 << (bits - 1))
    )


def rejects_single_value_tampers():
    for acc in [-3, -1, 0, 1, 3]:
        a, b = abs(acc), int(acc < 0)
        q, r = divmod(a + 1, 2)
        witness = (acc, a, b, q, r, (1 - 2 * b) * q)
        assert accepts_relation(acc, 1, 1, 8, witness)
        for index in range(len(witness)):
            tampered = list(witness)
            tampered[index] += 1
            assert not accepts_relation(acc, 1, 1, 8, tampered), index
    assert not accepts_relation(0, 1, 1, 8, (0, 0, 1, 0, 1, 0))  # Noncanonical zero sign.
    assert not accepts_relation(128, 1, 0, 8, (128, 128, 0, 128, 0, 128))  # Target overflow.
    assert not accepts_relation(-1, 1, 1, 8, (-1, 1, 1, 1, 0, 0))  # Wrong negative tie.
    assert not accepts_relation(1, 1, 1, 8, (1, 1, 0, 0, 2, 0))  # r = D.


def check():
    rejects_single_value_tampers()
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
