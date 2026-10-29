"""Q26 candidate scale alignment; no Accepted inference/reduction behavior."""
from quantiser import require


def fractional_bits(value):
    require(type(value) is int and 0 <= value <= 30, 'FractionalBits')


def round_i16(value, shift):
    """Exact signed shift; avoid constructing a large power for certain outcomes."""
    require(type(value) is int and abs(value) < 1 << 63, 'Product')
    require(type(shift) is int, 'Shift')
    magnitude = abs(value)
    if shift >= 64:
        rounded = 0  # Magnitude is strictly below the half unit 2^63.
    elif shift >= 0:
        divisor = 1 << shift
        rounded, remainder = divmod(magnitude, divisor)
        rounded += int(shift > 0 and 2*remainder >= divisor)
    elif magnitude == 0:
        rounded = 0
    else:
        require(-shift <= 15, 'Overflow')
        rounded = magnitude << -shift
    result = -rounded if value < 0 else rounded
    require(-32768 <= result <= 32767, 'Overflow')
    return result


def matmul_output(acc, mw, sx, ew, fx, fout, mode):
    """R(acc*mw*sx*2^(ew-fx+fout)), after the exact integer dot product."""
    require(type(acc) is int and -(1 << 31) <= acc < 1 << 31, 'Accumulator')
    require(type(mw) is int and 1 <= mw <= 65535, 'WeightScale')
    require(type(ew) is int and -1099 <= ew <= 1024, 'WeightExponent')
    fractional_bits(fx); fractional_bits(fout)
    require(type(mode) is str and mode in ('dynamic', 'static'), 'Mode')
    low, high = (0,259) if mode == 'dynamic' else (1,65535)
    require(type(sx) is int and low <= sx <= high, 'InputScale')
    if sx == 0:
        require(acc == 0, 'ZeroScale')
    # |acc|*65535^2 < 2^63, even at the negative int32 endpoint.
    return round_i16(acc*mw*sx, fx-ew-fout)


def residual(left, fl, right, fr, fout):
    """Align exactly, add, then round once into the configured target units."""
    require(all(type(x) is int and -32768 <= x <= 32767 for x in (left,right)), 'Input')
    for f in (fl,fr,fout): fractional_bits(f)
    common = max(fl,fr,fout)
    total = (left << (common-fl))+(right << (common-fr))
    # Two aligned int16 values have total magnitude at most 2^46.
    return round_i16(total,common-fout)
