"""Draft RFC-0025: numerical temperature/CDF/seed helpers, no proof admission."""
from math import gcd

from blake3 import blake3

from numerics import integer, round_ratio, row


def rational(numerator, denominator, top_p=False):
    integer(numerator, 1, (1 << 32)-1, 'Rational')
    integer(denominator, 1, (1 << 32)-1, 'Rational')
    if gcd(numerator, denominator) != 1 or (top_p and numerator > denominator):
        raise ValueError('Rational')


def temperature(logits, fraction, numerator, denominator, exp_fraction, exp_bits):
    """The accepted exp function must separately consume every returned argument."""
    if type(logits) is not list or not 1 <= len(logits) <= 1 << 20:
        raise ValueError('Vocabulary')
    row(logits, len(logits))
    for value in (fraction, exp_fraction):
        integer(value, 0, 30, 'Fraction')
    integer(exp_bits, 7, 31, 'ExpBits')
    rational(numerator, denominator)
    maximum = max(logits)
    scaled = [round_ratio((x-maximum)*denominator*(1 << exp_fraction),
                          numerator*(1 << fraction)) for x in logits]
    if any(x < -(1 << exp_bits) for x in scaled):
        raise ValueError('ExpDomain')
    return scaled


def select(weights, numerator, denominator, draw):
    """Conditional on the actual configured exp outputs; supplied weights are not authority."""
    if type(weights) is not list or not 1 <= len(weights) <= 1 << 20:
        raise ValueError('Vocabulary')
    for weight in weights:
        integer(weight, 0, 1 << 14, 'Weight')
    rational(numerator, denominator, top_p=True)
    integer(draw, 0, (1 << 32)-1, 'Draw')
    total = sum(weights)
    if total == 0:
        raise ValueError('ZeroMass')
    order = sorted(range(len(weights)), key=lambda i: (-weights[i], i))
    prefix = 0
    retained = []
    for index in order:
        prefix += weights[index]
        retained.append(prefix)
        if denominator*prefix >= numerator*total:
            break
    cdf = [(value << 32)//prefix for value in retained]
    selected = next(index for index, upper in enumerate(cdf) if draw < upper)
    return order[selected], tuple(order), tuple(cdf)


def seed_values(seed, position):
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError('Seed')
    integer(position, 0, (1 << 20)-1, 'Position')
    commitment = blake3(b'stele/v0.1/cqis/sample-seed'+seed).digest()
    raw = blake3(b'stele/v0.1/cqis/sample-draw'+seed+position.to_bytes(4, 'little')).digest()
    return commitment, int.from_bytes(raw[:4], 'little')
