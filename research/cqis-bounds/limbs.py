"""Q26 / Draft RFC-0004 A3: static nonnegative limb-column research only."""
from dataclasses import asdict, dataclass

P = 2**31-1


@dataclass(frozen=True)
class Spec:
    count: int
    left_max: int
    right_max: int
    radix_bits: int


def derive(spec):
    """The expected Spec models trusted static data, not a supplied certificate."""
    if (type(spec) is not Spec or any(type(v) is not int for v in asdict(spec).values())
            or not 1 <= spec.count < 2**32 or spec.radix_bits not in (4,8)
            or not 0 <= spec.left_max < 2**160 or not 0 <= spec.right_max < 2**160):
        raise ValueError('Spec')
    radix = 1 << spec.radix_bits
    def width(value):
        return max(1,(value.bit_length()+spec.radix_bits-1)//spec.radix_bits)
    def caps(value, length):
        return tuple(min(radix-1,value >> (i*spec.radix_bits)) for i in range(length))
    a,b = caps(spec.left_max,width(spec.left_max)),caps(spec.right_max,width(spec.right_max))
    result_max = spec.count*spec.left_max*spec.right_max
    columns = max(len(a)+len(b)-1,width(result_max))
    out = caps(result_max,columns)
    carry,lhs,rhs = [0],[],[]
    for k in range(columns):
        coefficient = spec.count*sum(x*b[k-i] for i,x in enumerate(a) if 0 <= k-i < len(b))
        left = coefficient+carry[k]
        # The final zero is an enforced boundary, justified by whole input ranges.
        carry.append(left//radix if k+1 < columns else 0)
        lhs.append(left)
        rhs.append(out[k]+radix*carry[k+1])
    if any(2*v >= P for v in lhs+rhs):
        raise ValueError('FieldBound')
    return dict(asdict(spec),prime=P,result_max=result_max,left_caps=a,right_caps=b,
                result_caps=out,carry_caps=tuple(carry),lhs=tuple(lhs),rhs=tuple(rhs))


def validate(spec, supplied):
    expected = derive(spec)
    if type(supplied) is not dict or supplied.keys() != expected.keys():
        raise ValueError('Certificate')
    for key,value in expected.items():
        actual = supplied[key]
        if (type(actual) is not type(value) or actual != value or
                (type(value) is tuple and any(type(v) is not int for v in actual))):
            raise ValueError('Certificate')
    return expected


def inputs(spec,left,right):
    for row,limit in ((left,spec.left_max),(right,spec.right_max)):
        if (type(row) is not tuple or len(row) != spec.count or
                any(type(v) is not int or not 0 <= v <= limit for v in row)):
            raise ValueError('InputRange')


def digits(value,bits,length):
    return tuple((value >> (bits*i)) & ((1 << bits)-1) for i in range(length))


def witness(spec,left,right):
    cert = derive(spec)  # Reject unsafe static bounds before inspecting values.
    inputs(spec,left,right)
    a = tuple(digits(v,spec.radix_bits,len(cert['left_caps'])) for v in left)
    b = tuple(digits(v,spec.radix_bits,len(cert['right_caps'])) for v in right)
    carry,result = [0],[]
    for k in range(len(cert['result_caps'])):
        column = sum(x*br[k-i] for ar,br in zip(a,b) for i,x in enumerate(ar)
                     if 0 <= k-i < len(br))
        quotient,remainder = divmod(column+carry[-1],1 << spec.radix_bits)
        carry.append(quotient)
        result.append(remainder)
    return dict(left=a,right=b,result=tuple(result),carry=tuple(carry))


def check_relations(spec,supplied,left,right,provided):
    """Plaintext research checker: no PCS, range lookup or proof verification."""
    cert = validate(spec,supplied)
    inputs(spec,left,right)
    if type(provided) is not dict or set(provided) != {'left','right','result','carry'}:
        raise ValueError('Witness')
    for side,row in (('left',left),('right',right)):
        values = provided[side]
        if (type(values) is not tuple or len(values) != spec.count or
                any(type(ds) is not tuple or any(type(v) is not int for v in ds) for ds in values)):
            raise ValueError('Witness')
        expected = tuple(digits(v,spec.radix_bits,len(cert[side+'_caps'])) for v in row)
        if values != expected:
            raise ValueError('SourceDigits')
    out,carry = provided['result'],provided['carry']
    for row,bounds in ((out,cert['result_caps']),(carry,cert['carry_caps'])):
        if type(row) is not tuple or len(row) != len(bounds) or any(type(v) is not int for v in row):
            raise ValueError('Witness')
    if carry[0] != 0 or carry[-1] != 0:
        raise ValueError('Boundary')
    for row,bounds in ((out,cert['result_caps']),(carry,cert['carry_caps'])):
        if any(not 0 <= v <= cap for v,cap in zip(row,bounds)):
            raise ValueError('Range')
    for k,value in enumerate(out):
        column = sum(x*br[k-i] for ar,br in zip(provided['left'],provided['right'])
                     for i,x in enumerate(ar) if 0 <= k-i < len(br))
        if (column+carry[k]-value-(1 << spec.radix_bits)*carry[k+1]) % P:
            raise ValueError('Relation')
    return sum(v << (spec.radix_bits*i) for i,v in enumerate(out))
