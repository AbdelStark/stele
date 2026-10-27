"""Research-only checks for proposed RFC-0003 A1; not a protocol implementation."""
from math import isqrt

P = (1 << 31) - 1


def multiply(a, b, modulus):
    """Schoolbook product modulo a monic polynomial; coefficients are low first."""
    degree = len(modulus) - 1
    assert len(a) == len(b) == degree and modulus[-1] == 1
    product = [0] * (2 * degree - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            product[i + j] += x * y
    for i in range(len(product) - 1, degree - 1, -1):
        for j in range(degree):
            product[i - degree + j] -= product[i] * modulus[j]
    return tuple(x % P for x in product[:degree])


def power(base, exponent, modulus):
    result = (1,) + (0,) * (len(base) - 1)
    while exponent:
        if exponent & 1:
            result = multiply(result, base, modulus)
        base = multiply(base, base, modulus)
        exponent >>= 1
    return result


def accepts_quadratic_constant(value, order, modulus):
    return power(value, (order - 1) // 2, modulus) == (P - 1,) + (0,) * (len(value) - 1)


def check():
    # Trial division proves primality here; no probabilistic primality assumption.
    assert P % 2 and all(P % d for d in range(3, isqrt(P) + 1, 2))
    assert P % 4 == 3
    assert pow(5, (P - 1) // 2, P) == P - 1
    cm = (1, 0, 1)  # i^2 + 1
    qm = (5, 0, -4, 0, 1)  # u^4 - 4u^2 + 5; i = u^2 - 2
    assert multiply((0, 1), (0, 1), cm) == (P - 1, 0)
    assert power((0, 1, 0, 0), 4, qm) == (P - 5, 0, 4, 0)
    assert power((2, 1), (P**2 - 1) // 2, cm) == (P - 1, 0)
    assert power((0, 1, 0, 0), (P**4 - 1) // 2, qm) == (P - 1, 0, 0, 0)
    assert accepts_quadratic_constant((0, 1, 0, 0), P**4, qm)
    # Replacing only the proposed constant by zero or a square must reject it.
    for value in [(0, 0, 0, 0), (1, 0, 0, 0), (4, 0, 0, 0)]:
        assert not accepts_quadratic_constant(value, P**4, qm)
    print("PASS: p prime; 5, 2+i and u nonsquare in their respective fields")


if __name__ == "__main__":
    check()
