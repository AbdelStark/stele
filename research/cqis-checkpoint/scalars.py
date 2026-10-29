"""Q26 candidate exact checkpoint scalar decoding; research, not CQIS admission."""

# Each tuple is byte width, stored exponent bits, stored fraction bits.
FORMATS = {'binary16': (2, 5, 10), 'bfloat16': (2, 8, 7),
           'binary32': (4, 8, 23), 'binary64': (8, 11, 52)}


def decode(name, raw):
    """Return canonical (signed odd significand, exponent), with zero=(0,0)."""
    if type(name) is not str or name not in FORMATS:
        raise ValueError('Format')
    size, eb, fb = FORMATS[name]
    if type(raw) is not bytes or len(raw) != size:
        raise ValueError('Length')
    word = int.from_bytes(raw, 'little')
    exponent = (word >> fb) & ((1 << eb)-1)
    fraction = word & ((1 << fb)-1)
    if exponent == (1 << eb)-1:
        raise ValueError('Nonfinite')
    bias = (1 << (eb-1))-1
    if exponent:
        significand, power = (1 << fb)+fraction, exponent-bias-fb
    else:
        significand, power = fraction, 1-bias-fb
    if significand == 0:
        return 0, 0
    while significand % 2 == 0:
        significand //= 2
        power += 1
    if word >> (size*8-1):
        significand = -significand
    return significand, power
