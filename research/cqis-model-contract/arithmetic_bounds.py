"""Draft RFC-0025 static appendix §§1–6: closed arithmetic records, no proof API."""
from dataclasses import dataclass

from numerics import LayerNorm, group, integer

P = (1 << 31)-1
WORD_BYTES = 288
CAPACITY = 1 << 17
PREFIX = b'stele/v0.1/cqis/model-arithmetic'


def _weight(bits, exponent, mantissa):
    integer(bits, 4, 8, 'Weight')
    if bits not in (4, 8):
        raise ValueError('Weight')
    integer(exponent, -1099, 1024, 'Weight')
    integer(mantissa, 1, 65535, 'Weight')


@dataclass(frozen=True)
class Affine:
    inner: int
    bits: int
    exponent: int
    mantissa: int
    kind: int
    fraction: int
    output_fraction: int
    policy: int
    scale: int
    bias_fraction: int | None
    output_bits: int = 16  # 24 is RFC-0004 A14's wide O/down output, schema 21

    def __post_init__(self):
        if self.output_bits not in (16, 24) or (self.output_bits == 24 and self.bias_fraction is not None):
            raise ValueError('Width')
        integer(self.inner, 1, 16384, 'Shape')
        _weight(self.bits, self.exponent, self.mantissa)
        integer(self.kind, 0, 1, 'Kind')
        integer(self.fraction, 0, 44 if self.kind else 30, 'Fraction')
        integer(self.output_fraction, 0, 30, 'Fraction')
        integer(self.policy, 0, 2, 'Policy')
        if self.policy == 2:  # RFC-0004 A15 grouped dynamic row: scale carries the group size
            group(self.scale, self.inner, 'Scale')
        else:
            integer(self.scale, 1 if self.policy else 0,
                    (8454661 if self.kind else 65535) if self.policy else 0, 'Scale')
        if self.bias_fraction is not None:
            integer(self.bias_fraction, 0, 30, 'Bias')

    def parameters(self):
        raw = (_unsigned(self.inner, 2)+_unsigned(self.bits, 1)+_signed(self.exponent)+
               _unsigned(self.mantissa, 2)+bytes((self.kind, self.fraction, self.output_fraction,
                                               self.policy))+_unsigned(self.scale, 4)+
               bytes((int(self.bias_fraction is not None),)))
        return raw+(bytes((self.bias_fraction,)) if self.bias_fraction is not None else b'')


@dataclass(frozen=True)
class Embedding:
    vocabulary: int
    context: int
    output_fraction: int
    bits: int
    exponent: int
    mantissa: int
    position: tuple | None

    def __post_init__(self):
        integer(self.vocabulary, 1, 1 << 20, 'Shape')
        integer(self.context, 1, 1 << 20, 'Shape')
        integer(self.output_fraction, 0, 30, 'Fraction')
        _weight(self.bits, self.exponent, self.mantissa)
        if self.position is not None:
            if type(self.position) is not tuple or len(self.position) != 3:
                raise ValueError('Position')
            _weight(*self.position)

    def parameters(self):
        raw = (_unsigned(self.vocabulary, 4)+_unsigned(self.context, 4)+
               bytes((self.output_fraction, self.bits))+_signed(self.exponent)+
               _unsigned(self.mantissa, 2)+bytes((int(self.position is not None),)))
        if self.position is not None:
            bits, exponent, mantissa = self.position
            raw += bytes((bits,))+_signed(exponent)+_unsigned(mantissa, 2)
        return raw


def _unsigned(value, size):
    integer(value, 0, (1 << (8*size))-1, 'Capacity')
    return value.to_bytes(size, 'little')


def _signed(value):
    integer(value, -(1 << 15), (1 << 15)-1, 'Capacity')
    return value.to_bytes(2, 'little', signed=True)


def _caps(maximum, bits=8):
    integer(maximum, 0, (1 << (8*WORD_BYTES))-1, 'Capacity')
    width = max(1, (maximum.bit_length()+(bits-1))//bits)
    return tuple(min((1 << bits)-1, maximum >> (bits*i)) for i in range(width))


def _column(terms, bits=8):
    """Private derivation from closed roles; never trusted caller-supplied terms."""
    z = sum(n*a*c for n, a, c in terms)
    operands = tuple((n, a, c, _caps(a, bits), _caps(c, bits)) for n, a, c in terms)
    size = max(len(_caps(z, bits)), *(len(a)+len(c)-1 for _, _, _, a, c in operands))
    if size > 269:
        raise ValueError('Capacity')
    result = tuple(min((1 << bits)-1, z >> (bits*i)) for i in range(size))
    raw = [0]*size
    for n, _, _, a, c in operands:
        for i, left in enumerate(a):
            for j, right in enumerate(c):
                raw[i+j] += n*left*right
    carries = [0]
    for value in raw[:-1]:
        carries.append((value+carries[-1])//(1 << bits))
    carries.append(0)
    left = tuple(raw[i]+carries[i] for i in range(size))
    right = tuple(result[i]+(1 << bits)*carries[i+1] for i in range(size))
    if any(2*side >= P for side in left+right):
        raise ValueError('FieldBound')
    return operands, z, result, tuple(carries), left, right


def digit_bounds(kind):
    """RFC-0004 A15: a folded value s*q of a grouped row has |s*q| <= X = 127*smax and is
    written as T signed radix-256 digits, each low digit in [-128,127]; returns (smax, X, T, top),
    top bounding the last digit. Balanced digits are the unsigned digits of s*q+c, so the top
    digit is monotone in s*q and its extremes are at -X and X."""
    smax = 8454661 if kind else 259
    x, count = 127*smax, 4 if kind else 2
    offset = 128*((1 << (8*(count-1)))-1)//255
    top = max(abs((v+offset) >> (8*(count-1))) for v in (-x, x))
    if top > 128:
        raise ValueError('FieldBound')
    return smax, x, count, top


def _rounding_roles(maximum, divisor, output=32768):
    quotient = min(output, maximum//divisor)
    return (
        ((1, 2*maximum, 1), (1, maximum, 2)),
        ((1, maximum, 1), (1, maximum, 1)),
        ((1, quotient, divisor),),
        ((1, quotient*divisor, 1), (1, divisor-1, 1)),
        ((1, divisor-1, 1), (1, divisor-1, 1), (1, 1, 1)),
        ((1, divisor-1, 2),),
        ((1, 2*divisor-2, 1), (1, divisor-1, 1), (1, 1, 1)),
        ((1, divisor, 1), (1, divisor-1, 1)),
    )


def _layernorm(p):
    """Schema 3: common bounds retain the joint exponent/source obligations."""
    h, o = 32768, 65535
    s, os, q, c, v = p.d*h, p.d*o, p.d*h*h, o*(p.d-1), p.d*p.d*h*h
    unit = p.d*p.d << (2*p.F)
    n, denominator = p.ed*v+p.en*unit, p.ed*unit
    fa, fd = 1 << 46, 1 << 18
    aa, dd = n*fa, denominator*fd
    md, ch = 65535*dd, c*h
    t = ch*16384
    branches = []
    for a in range(-23, 10):
        e = p.F+p.G+21+a-p.E
        k = max(e, p.Gb-p.E, 0)
        branches.append((e, k, 1 << (k-e), 1 << (k+p.E-p.Gb), 1 << k))
    lt, lb, power = (max(row[i] for row in branches) for i in (2, 3, 4))
    dlb, dout = p.d*lb, p.d*power
    maximum = t*lt+h*dlb
    quotient, qd = 32768, 32768*dout
    scalars = (h, o, s, os, q, c, v, unit, n, denominator, fa, fd, aa, dd, md,
               16384, ch, t, lt, lb, power, dlb, maximum, dout, quotient, qd, 131071, 65536)
    shifts = (min(row[0] for row in branches), max(row[0] for row in branches),
              min(row[1] for row in branches), max(row[1] for row in branches))
    roles = (
        ((p.d, o, 1),), ((p.d, h, h),),
        ((1, os, 1), (1, s, 2)), ((1, s, 1), (1, s, 1)),
        ((1, o, p.d), (1, c, 1)), ((1, 2*c, 1), (1, os, 1)),
        ((1, 2*c, 1), (1, c, 2)), ((1, c, 1), (1, c, 1)),
        ((1, s, s),), ((1, q, p.d),), ((1, v, 1), (1, v, 1)),
        ((1, v, p.ed), (1, unit, p.en)), ((1, n, fa),), ((1, denominator, fd),),
        ((1, 65535, dd),), ((1, md, 1), (1, dd-1, 1)),
        ((1, dd-1, 1), (1, dd-1, 1), (1, 1, 1)),
        ((1, c, h),), ((1, ch, 16384),),
        ((1, 2*t, 1), (1, t, 2)), ((1, t, 1), (1, t, 1)),
        ((1, p.d, lb),), ((1, t, lt), (1, h, dlb)),
        ((1, 2*t, lt), (1, o, dlb)),
        ((1, 2*maximum, 1), (1, maximum, 2)), ((1, maximum, 1), (1, maximum, 1)),
        ((1, p.d, power),), ((1, quotient, dout),),
        ((1, qd, 1), (1, dout-1, 1)),
        ((1, dout-1, 1), (1, dout-1, 1), (1, 1, 1)),
        ((1, dout-1, 2),), ((1, 2*dout-2, 1), (1, dout-1, 1), (1, 1, 1)),
        ((1, dout, 1), (1, dout-1, 1)),
    )
    for scalar in scalars:
        _caps(scalar)
    return 3, scalars, shifts, tuple(_column(terms) for terms in roles)


def _grouped_affine(p):
    """Schemas 24/25 (RFC-0004 A15): schema 1/21 with roles 1-2 replaced by the digit rows.

    Each digit row t is one field matmul C_t = sum_i b_t,i*w_i with |b| <= 128 and
    |C_t| <= cmax_t, so 8*inner*128*weight < p keeps it faithful. The offsets
    U_t = C_t+cmax_t are bounded by W_t = 2*cmax_t-U_t (both four range_8 bytes, joined
    U_t+W_t = 2*cmax_t in a byte column) and recombined in byte columns with the signed join
    sum_t 256^t*U_t + 2*sign*|A'| = V + |A'|, V = sum_t 256^t*cmax_t; then |A'| times the
    mantissa. |A'| <= amax = inner*X*weight, so the total, maximum and rounding roles equal
    schema 1/21's at the dynamic row-scale maximum."""
    weight = (1 << (p.bits-1))-1
    smax, x, count, top = digit_bounds(p.kind)
    digits = tuple(p.inner*weight*(128 if t < count-1 else top) for t in range(count))
    cmax = max(digits)
    if 8*cmax >= P:
        raise ValueError('FieldBound')
    amax = p.inner*x*weight
    v = sum(c << (8*t) for t, c in enumerate(digits))
    total = amax*p.mantissa
    le = p.exponent-p.fraction+p.output_fraction
    re = p.output_fraction-p.bias_fraction if p.bias_fraction is not None else 0
    shift = max(0, -le, -re)
    divisor, left = 1 << shift, 1 << (le+shift)
    bias = (1 << (re+shift)) if p.bias_fraction is not None else 0
    maximum = total*left+32768*bias
    output = 1 << (p.output_bits-1)
    scalars = (weight, smax, x, count, top, cmax, amax, v, total, divisor, left, bias, maximum,
               min(output, maximum//divisor), output, 4*cmax, 2*cmax, 2*v, 4*output-1, 2*output)
    aligned = ((1, 2*total, left),)
    if bias:
        aligned += ((1, 65535, bias),)
    offsets = tuple((1, 2*c, 1 << (8*t)) for t, c in enumerate(digits))
    bounded = tuple(((1, 2*c, 1), (1, 2*c, 1)) for c in digits)  # U_t + W_t = 2*cmax_t
    roles = (offsets,)+bounded+(((1, 2*v, 1), (1, amax, 2)), ((1, v, 1), (1, amax, 1)), ((1, amax, p.mantissa),),
             ((1, 2*total, 1), (1, total, 2)), ((1, total, 1), (1, total, 1)), aligned)
    roles += _rounding_roles(maximum, divisor, output)
    for scalar in scalars:
        _caps(scalar)
    return (24 if p.output_bits == 16 else 25), scalars, (le, re, shift), tuple(_column(t) for t in roles)


def derive(parameters):
    """Static metadata only: no values, source handles, field or arbitrary ops."""
    if type(parameters) is LayerNorm:
        return _layernorm(parameters)
    if type(parameters) is Affine and parameters.policy == 2:
        return _grouped_affine(parameters)
    if type(parameters) is Affine:
        p = parameters
        weight = (1 << (p.bits-1))-1
        scale = p.scale if p.policy else (8454661 if p.kind else 259)
        accumulator = 127*weight*p.inner
        product = accumulator*p.mantissa
        total = product*scale
        le = p.exponent-p.fraction+p.output_fraction
        re = p.output_fraction-p.bias_fraction if p.bias_fraction is not None else 0
        shift = max(0, -le, -re)
        divisor, left = 1 << shift, 1 << (le+shift)
        bias = (1 << (re+shift)) if p.bias_fraction is not None else 0
        maximum = total*left+32768*bias
        if 8*accumulator >= P:
            raise ValueError('FieldBound')
        output = 1 << (p.output_bits-1)
        scalars = (weight, scale, accumulator, product, total, divisor, left, bias,
                   maximum, min(output, maximum//divisor), output, 4*accumulator, 2*accumulator,
                   4*output-1, 2*output)
        shifts = (le, re, shift)
        aligned = ((1, 2*total, left),)
        if bias:
            aligned += ((1, 65535, bias),)
        roles = (((1, accumulator, p.mantissa),), ((1, product, scale),),
                 ((1, 2*total, 1), (1, total, 2)), ((1, total, 1), (1, total, 1)), aligned)
        schema = 1 if p.output_bits == 16 else 21
    elif type(parameters) is Embedding:
        p = parameters
        source = [(p.bits, p.exponent, p.mantissa)]
        if p.position is not None:
            source.append(p.position)
        limits = tuple(((1 << (bits-1))-1)*m for bits, _, m in source)
        exponents = tuple(e+p.output_fraction for _, e, _ in source)
        shift = max(0, *(-e for e in exponents))
        divisor = 1 << shift
        factors = tuple(1 << (e+shift) for e in exponents)
        maximum = sum(a*f for a, f in zip(limits, factors))
        scalars = ((p.vocabulary-1, p.context-1)+limits+(divisor,)+factors+
                   (maximum, min(32768, maximum//divisor), 32768)+
                   tuple(side for a in limits for side in (4*a, 2*a))+(131071, 65536))
        shifts = exponents+(shift,)
        roles = tuple(((1, (1 << (bits-1))-1, m),) for bits, _, m in source)
        roles += (tuple((1, 2*a, f) for a, f in zip(limits, factors)),)
        schema = 2
    else:
        raise ValueError('Parameters')
    roles += _rounding_roles(maximum, divisor, output if type(parameters) is Affine else 32768)
    for scalar in scalars:
        _caps(scalar)
    return schema, tuple(scalars), shifts, tuple(_column(terms) for terms in roles)


def encode(parameters):
    record = derive(parameters)
    if type(parameters) is LayerNorm:
        p = parameters
        params = (_unsigned(p.d, 2)+bytes((p.F, p.G, p.E, p.Gb))+
                  _unsigned(p.en, 4)+_unsigned(p.ed, 4))
    else:
        params = parameters.parameters()
    return _encode_record(params, *record)


def _encode_record(params, schema, scalars, shifts, roles, *, bits=8):
    """Shared private framing; public callers derive only their closed schemas."""
    chunks = [PREFIX, _unsigned(1, 4), bytes((schema,)), _unsigned(len(params), 2), params,
              _unsigned(P, 4), bytes((bits, len(scalars)))]
    chunks.extend(_unsigned(value, WORD_BYTES) for value in scalars)
    chunks.append(bytes((len(shifts),)))
    chunks.extend(_signed(value) for value in shifts)
    chunks.append(bytes((len(roles),)))
    for index, (terms, z, result, carries, left, right) in enumerate(roles, 1):
        chunks.append(bytes((index, len(terms))))
        for n, a, c, ac, cc in terms:
            chunks.extend((_unsigned(n, 4), _unsigned(a, WORD_BYTES), _unsigned(c, WORD_BYTES),
                           _unsigned(len(ac), 2), _unsigned(len(cc), 2), bytes(ac), bytes(cc)))
        chunks.extend((_unsigned(z, WORD_BYTES), _unsigned(len(result), 2), bytes(result)))
        chunks.extend(_unsigned(value, 4) for value in carries+left+right)
    if sum(map(len, chunks)) > CAPACITY:
        raise ValueError('Capacity')
    return b''.join(chunks)


def validate(expected, supplied):
    if type(supplied) is not bytes or len(supplied) > CAPACITY:
        raise ValueError('Capacity')
    if supplied != encode(expected):
        raise ValueError('Encoding')
