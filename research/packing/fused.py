"""Q28 one-visit algebra prototype; no authenticated source or PCS authority."""
from dataclasses import dataclass
from check_sumcheck import scalar, add, mul, neg, P
from packing import require


def dimensions(shape):
    require(type(shape) in (tuple, list) and len(shape) == 3, 'Shape')
    require(all(type(n) is int and n > 0 for n in shape), 'Shape')
    return tuple(1 << (n-1).bit_length() for n in shape)


def coefficients(point, d):
    values = [scalar(1, d)]
    for r in point:
        values = [mul(v, z) for v in values for z in (add(scalar(1, d), neg(r)), r)]
    return values


class Source:
    """Logical-value read instrumentation, not IO/DRAM or process-memory evidence."""
    def __init__(self, values):
        self.values = values
        self.reads = self.visits = 0

    def visit(self, count, width):
        require(self.visits == 0, 'SourceReused')
        require(len(self.values) == count, 'SourceLength')
        self.visits += 1

        def values():
            for value in self.values:
                self.reads += 1
                require(type(value) is int and -(1 << (width-1)) <= value < 1 << (width-1), 'SourceRange')
                yield value
        return values()


@dataclass(frozen=True)
class Partial:
    row: tuple
    b: tuple
    retained: int
    coefficients: int
    source_macs: int
    fold_macs: int


def partial(source, shape, width, point, split, d):
    require(type(d) is int and d in (4, 8), 'Field')
    lp, ip, jp = dimensions(shape)
    require(type(width) is int and width in (8, 16), 'Width')
    bits = jp.bit_length()-1
    require(type(split) is int and 0 <= split <= bits, 'Split')
    require(type(point) in (tuple, list) and len(point) == bits
            and all(type(r) in (tuple, list) and len(r) == d
                    and all(type(v) is int and 0 <= v < P for v in r) for r in point), 'Point')
    t, lows = lp*ip, 1 << split
    high = coefficients(point[:bits-split], d)
    low = coefficients(point[bits-split:], d)
    row = [scalar(0, d)]*(lows*t)
    layers, inner, outputs = shape
    # Visit only original values. Signed embedding scales every extension limb.
    for index, value in enumerate(source.visit(layers*inner*outputs, width)):
        ell = index//(inner*outputs)
        k, j = index//outputs % inner, index % outputs
        at = (j % lows)*t+ell*ip+k
        row[at] = add(row[at], tuple(value*v % P for v in high[j//lows]))
    row = tuple(row)
    b = row
    if split:
        folded = [scalar(0, d)]*t
        for lo in range(lows):
            for column in range(t):
                folded[column] = add(folded[column], mul(low[lo], row[lo*t+column]))
        b = tuple(folded)
    # Logical retained counts exclude transient Python objects and all PCS work.
    return Partial(row, b, len(row)+(len(b) if split else 0), len(high)+len(low),
                   source.reads, len(row) if split else 0)


def payload(t, j, split, d, queries):
    require(all(type(n) is int and n > 0 and n & (n-1) == 0 for n in (t, j)), 'Shape')
    require(type(split) is int and 0 <= split < j.bit_length(), 'Split')
    require(type(d) is int and d in (4, 8), 'Field')
    require(type(queries) is int and queries > 0, 'Queries')
    columns, rows = t*(1 << split), j >> split
    return dict(message_symbols=t*j, row_bytes=4*d*columns, column_bytes=4*queries*rows,
                retained_symbols=columns+(t if split else 0))
