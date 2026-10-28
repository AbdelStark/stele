#!/usr/bin/env python3
"""Exact counterexamples to RFC-0004 §§4,5.3; research, not table semantics."""

from fractions import Fraction


def normalization(statistic):
    """S=M*4**a forces bit_length(S)=16+2*a, including negative a."""
    if statistic <= 0 or statistic.bit_length() % 2:
        return None
    exponent = (statistic.bit_length() - 16) // 2
    mantissa = Fraction(statistic) / Fraction(4) ** exponent
    if mantissa.denominator != 1:
        return None
    assert 2**15 <= mantissa < 2**16
    return int(mantissa), exponent


def main():
    domain = range(-(2**14), 1)
    high = {value >> 7 for value in domain}
    low = {value & 127 for value in domain}
    assert len(domain) == 16_385 != 2**14
    assert high == set(range(-128, 1)) and len(high) == 129 != 128
    assert low == set(range(128))
    assert all(value == 128 * (value >> 7) + (value & 127) for value in domain)
    # The extra high index is the required exp_q(0) endpoint, not padding.
    assert (domain.start >> 7, 0 >> 7) == (-128, 0)

    witnesses = [(0,), (1,), (256,), (256, 256, 1)]
    for values in witnesses:
        statistic = sum(value * value for value in values)
        assert normalization(statistic) is None, (values, statistic)
    assert [sum(x * x for x in row) for row in witnesses] == [0, 1, 65_536, 131_073]
    assert normalization(2) == (32_768, -7)
    assert normalization(131_072) == (32_768, 1)

    # Independent finite search. For 1<=S<=2**44, a<-8 gives S<1 and
    # a>15 gives S>=2**47. Thus this search covers every possible exponent.
    statistics = [0, 1, 2, 3, 32_768, 65_535, 65_536, 131_072, 131_073, 2**44]
    statistics += [2**bits + offset for bits in range(1, 44) for offset in (-1, 0, 1)]
    for statistic in statistics:
        candidates = []
        for exponent in range(-8, 16):
            mantissa = Fraction(statistic) / Fraction(4) ** exponent
            if mantissa.denominator == 1 and 2**15 <= mantissa < 2**16:
                candidates.append((int(mantissa), exponent))
        result = normalization(statistic)
        assert candidates == ([] if result is None else [result])

    assert all(normalization(4**exponent) is None for exponent in range(23))
    print(f"exp domain=16385, high=129, low=128; {len(statistics)} exact normalization checks passed")
    print("valid int16 sum-of-squares counterexamples: 0, 1, 65536, 131073")


if __name__ == "__main__":
    main()
