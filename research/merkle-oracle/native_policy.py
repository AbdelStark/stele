"""Draft RFC-0010 A9 finite policy; not an admitted native parameter API."""
CERT_HALF = (130, 314, 314, 434, 434, 478, 478, 491, 491, 494, 494, 494, 494) + (495,)*17
OPEN_HALF = (1, 130, 192, 192, 214, 214, 221, 221, 222, 222) + (223,)*20
CERT_QUARTER = (130,) + (314,)*28
OPEN_QUARTER = (65, 92, 110, 119, 125, 128, 129) + (130,)*22


def counts(exponent, blowup):
    if (type(exponent) is not int or type(blowup) is not int
            or blowup not in (1, 2) or not 0 <= exponent <= 30-blowup):
        raise ValueError('UnsupportedParameters')
    cert, opening = (CERT_HALF, OPEN_HALF) if blowup == 1 else (CERT_QUARTER, OPEN_QUARTER)
    return cert[exponent], opening[exponent]


def decode_index(value, size, prime):
    """Pure candidate decoder, with small Mersenne primes for exhaustive checks."""
    if (type(value) is not int or type(size) is not int or type(prime) is not int
            or not 0 <= value < prime or size < 2 or size & (size-1)
            or size > (prime+1)//2):
        raise ValueError('InvalidCandidate')
    threshold = (prime//size)*size
    return value % size if value < threshold else None
