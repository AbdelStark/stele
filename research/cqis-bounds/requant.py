"""Q26 / RFC-0004 A1, Draft A3: closed scalar certificate research only."""
from dataclasses import asdict, dataclass
from itertools import zip_longest
import limbs

P = limbs.P


@dataclass(frozen=True)
class Spec:
    mantissa: int
    shift: int
    bits: int


def constants(spec):
    if (type(spec) is not Spec or any(type(v) is not int for v in asdict(spec).values())
            or not 1 <= spec.mantissa <= 65535 or not 0 <= spec.shift <= 62 or spec.bits not in (8,16)):
        raise ValueError('Spec')
    divisor = 1 << spec.shift
    bias = divisor//2 if spec.shift else 0
    product = (1 << 31)*spec.mantissa
    output = 1 << (spec.bits-1)
    return dict(asdict(spec),prime=P,divisor=divisor,bias=bias,product_max=product,
                quotient_max=min(output,(product+bias)//divisor),output_max=output,
                output_lhs_bound=4*output-1,output_rhs_bound=2*output)


def column_specs(spec):
    c = constants(spec)
    # Six fixed relations: callers cannot supply dimensions, formats or magnitudes.
    return dict(input_lhs=limbs.Spec(2,(1 << 32)-1,2,8),
                input_rhs=limbs.Spec(2,1 << 31,1,8),
                product=limbs.Spec(1,1 << 31,spec.mantissa,8),
                bias=limbs.Spec(2,max(c['product_max'],c['bias']),1,8),
                quotient_product=limbs.Spec(1,c['quotient_max'],c['divisor'],8),
                division=limbs.Spec(2,max(c['quotient_max']*c['divisor'],c['divisor']-1),1,8))


def derive(spec):
    c = constants(spec)
    if 2*max(c['output_lhs_bound'],c['output_rhs_bound']) >= P:
        raise ValueError('FieldBound')
    return dict(c,columns={name:limbs.derive(s) for name,s in column_specs(spec).items()})


def same(actual,expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(same(actual[k],v) for k,v in expected.items())
    if type(expected) is tuple:
        return len(actual) == len(expected) and all(same(a,b) for a,b in zip(actual,expected))
    return actual == expected


def validate(spec,supplied):
    expected = derive(spec)
    if not same(supplied,expected):
        raise ValueError('Certificate')
    return expected


def input_range(acc):
    if type(acc) is not int or not -(1 << 31) <= acc < 1 << 31:
        raise ValueError('Input')


def column_inputs(spec,acc,w):
    c = constants(spec)
    return dict(input_lhs=((acc+(1 << 31),w['magnitude']),(1,2*w['sign'])),
                input_rhs=((1 << 31,w['magnitude']),(1,1)),
                product=((w['magnitude'],),(spec.mantissa,)),
                bias=((w['product'],c['bias']),(1,1)),
                quotient_product=((w['quotient'],),(c['divisor'],)),
                division=((w['scaled_quotient'],w['remainder']),(1,1)))


def witness(spec,acc):
    derive(spec)
    input_range(acc)
    c = constants(spec)
    product = abs(acc)*spec.mantissa
    quotient,remainder = divmod(product+c['bias'],c['divisor'])
    output = -quotient if acc < 0 else quotient
    if not -c['output_max'] <= output < c['output_max']:
        raise ValueError('OutputRange')
    w = dict(sign=int(acc < 0),magnitude=abs(acc),product=product,quotient=quotient,
             scaled_quotient=quotient*c['divisor'],remainder=remainder,output=output)
    values = column_inputs(spec,acc,w)
    w['columns'] = {name:limbs.witness(s,*values[name]) for name,s in column_specs(spec).items()}
    return w


def equal_digits(left,right):
    # All digits have already been range checked. No wide equality modulo M31.
    if any((a-b) % P for a,b in zip_longest(left,right,fillvalue=0)):
        raise ValueError('IntegerRelation')


def check_relations(spec,supplied,acc,w):
    """Plaintext source/range model for six column relations and one small sign relation."""
    c = validate(spec,supplied)
    input_range(acc)
    fields = {'sign','magnitude','product','quotient','scaled_quotient','remainder','output'}
    if (type(w) is not dict or set(w) != fields | {'columns'} or
            any(type(w[name]) is not int for name in fields) or type(w['columns']) is not dict or
            w['columns'].keys() != c['columns'].keys()):
        raise ValueError('Witness')
    bounds = dict(sign=1,magnitude=1 << 31,product=c['product_max'],quotient=c['quotient_max'],
                  scaled_quotient=c['quotient_max']*c['divisor'],remainder=c['divisor']-1)
    if (any(not 0 <= w[k] <= limit for k,limit in bounds.items()) or
            not -c['output_max'] <= w['output'] < c['output_max']):
        raise ValueError('Range')
    if w['magnitude'] == 0 and w['sign'] != 0:
        raise ValueError('Sign')
    values = column_inputs(spec,acc,w)
    results = {}
    for name,s in column_specs(spec).items():
        record = w['columns'][name]
        limbs.check_relations(s,c['columns'][name],*values[name],record)
        results[name] = record['result']
    equal_digits(results['input_lhs'],results['input_rhs'])
    equal_digits(results['bias'],results['division'])
    for name,value in (('product',w['product']),('quotient_product',w['scaled_quotient'])):
        equal_digits(results[name],limbs.digits(value,8,max(1,(value.bit_length()+7)//8)))
    # Offset output is in [0,2H); both sides have strict static p/2 bounds.
    lhs = w['output']+c['output_max']+2*w['sign']*w['quotient']
    rhs = c['output_max']+w['quotient']
    if (lhs-rhs) % P:
        raise ValueError('OutputRelation')
    return w['output']
