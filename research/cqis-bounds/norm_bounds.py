"""Q26 / RFC-0021 §2.3: closed static arithmetic research, no proof consumer."""
from dataclasses import asdict, dataclass
from math import gcd, isqrt
import limbs
from requant import equal_digits, same

P = limbs.P
GLOBAL = ('S','N','A','MD','R','a','M','J')
ROW = ('x_magnitude','x_sign','g_magnitude','g_sign','product_sign','xy',
       'product','quotient','scaled_quotient','remainder','output')


@dataclass(frozen=True)
class Spec:
    d: int
    F: int
    G: int
    E: int
    en: int
    ed: int


def constants(p):
    if (type(p) is not Spec or any(type(v) is not int for v in asdict(p).values())
            or not 1 <= p.d <= 16384 or not 0 <= p.F <= 30 or not 0 <= p.G <= 30
            or not 0 <= p.E <= 14 or not 1 <= p.en < 2**32 or not 1 <= p.ed < 2**32
            or gcd(p.en,p.ed) != 1):
        raise ValueError('Spec')
    unit = p.d << (2*p.F)
    statistic = p.d << 30
    numerator = p.ed*statistic+p.en*unit
    denominator = p.ed*unit
    low,high = p.F+p.G-2-p.E,p.F+p.G+30-p.E
    return dict(asdict(p),prime=P,unit=unit,S_max=statistic,N_max=numerator,P=denominator,
                A_max=numerator << 46,D_max=denominator << 18,MD_max=65535*(denominator << 18),
                shift_min=low,shift_max=high,round_divisor_max=1 << max(0,high),
                round_bias_max=(1 << (high-1)) if high > 0 else 0,
                left_factor_max=1 << max(0,-low),sign_lhs=131071,sign_rhs=65536)


def column_specs(p):
    c = constants(p)
    s = lambda d,a,b: limbs.Spec(d,a,b,8)
    return dict(statistic=s(p.d,32768,32768),
                numerator=s(2,max(c['S_max'],c['unit']),max(p.ed,p.en)),
                scaled=s(1,c['N_max'],1 << 46),
                normal_product=s(1,65535,c['D_max']),normal_sum=s(2,c['MD_max'],1),
                xy=s(1,32768,32768),product=s(1,1 << 30,16384),
                bias=s(2,max(1 << 44,c['round_bias_max']),1),
                quotient_product=s(1,32768,c['round_divisor_max']),
                division=s(2,32768*c['round_divisor_max'],1),
                left=s(1,1 << 44,c['left_factor_max']))


def derive(p):
    c = constants(p)
    if 2*max(c['sign_lhs'],c['sign_rhs']) >= P:
        raise ValueError('FieldBound')
    return dict(c,columns={name:limbs.derive(s) for name,s in column_specs(p).items()})


def validate(p,supplied):
    expected = derive(p)
    if not same(supplied,expected):
        raise ValueError('Certificate')
    return expected


def inputs(p,xs,gs):
    if any(type(row) is not tuple or len(row) != p.d or
           any(type(v) is not int or not -32768 <= v <= 32767 for v in row) for row in (xs,gs)):
        raise ValueError('Input')


def reciprocal(m):
    root = isqrt((1 << 42)//m)
    return root+int((1 << 44) >= m*(2*root+1)**2)


def parameters(p,w):
    c = constants(p)
    factor = 1 << (-2*min(w['a'],0))
    denominator = c['P'] << (2*max(w['a'],0))
    shift = p.F+p.G+21+w['a']-p.E
    divisor = 1 << max(0,shift)
    bias = divisor//2 if shift > 0 else 0
    return factor,denominator,shift,divisor,bias


def column_inputs(p,w):
    c = constants(p)
    factor,D,shift,divisor,bias = parameters(p,w)
    magnitudes = tuple(row['x_magnitude'] for row in w['rows'])
    global_values = dict(statistic=(magnitudes,magnitudes),
                         numerator=((w['S'],c['unit']),(p.ed,p.en)),scaled=((w['N'],),(factor,)),
                         normal_product=((w['M'],),(D,)),normal_sum=((w['MD'],w['R']),(1,1)))
    rows = []
    for r in w['rows']:
        values = dict(xy=((r['x_magnitude'],),(r['g_magnitude'],)),product=((r['xy'],),(w['J'],)))
        if shift < 0:
            values['left'] = ((r['product'],),(1 << -shift,))
        else:
            values.update(bias=((r['product'],bias),(1,1)),
                          quotient_product=((r['quotient'],),(divisor,)),
                          division=((r['scaled_quotient'],r['remainder']),(1,1)))
        rows.append(values)
    return global_values,rows


def attach_columns(p,xs,gs,w):
    """Research witness construction; coherent forged facts still need all checks."""
    inputs(p,xs,gs)
    specs = column_specs(p)
    global_values,rows = column_inputs(p,w)
    w['columns'] = {name:limbs.witness(specs[name],*args) for name,args in global_values.items()}
    for row,values in zip(w['rows'],rows):
        row['columns'] = {name:limbs.witness(specs[name],*args) for name,args in values.items()}
    return w


def witness(p,xs,gs):
    c = derive(p)
    inputs(p,xs,gs)
    S = sum(x*x for x in xs)
    N = p.ed*S+p.en*c['unit']
    a = (N.bit_length()-c['P'].bit_length()-14)//2
    def scaled(a):
        return N << (-2*min(a,0)),c['P'] << (2*max(a,0))
    A,D = scaled(a)
    if A < 16384*D:
        a -= 1;A,D = scaled(a)
    M,R = divmod(A,D)
    w = dict(S=S,N=N,A=A,MD=M*D,R=R,a=a,M=M,J=reciprocal(M),rows=[])
    _,_,shift,divisor,bias = parameters(p,w)
    for x,g in zip(xs,gs):
        xy = abs(x*g);product = xy*w['J']
        sign = int((x < 0) != (g < 0) and xy != 0)
        quotient,remainder = divmod(product+bias,divisor) if shift >= 0 else (product << -shift,0)
        output = -quotient if sign else quotient
        if not -32768 <= output <= 32767:
            raise ValueError('OutputRange')
        w['rows'].append(dict(x_magnitude=abs(x),x_sign=int(x < 0),g_magnitude=abs(g),g_sign=int(g < 0),
                              product_sign=sign,xy=xy,product=product,quotient=quotient,
                              scaled_quotient=quotient*divisor if shift >= 0 else 0,
                              remainder=remainder,output=output))
    return attach_columns(p,xs,gs,w)


def source_sign(value,magnitude,sign):
    if magnitude == 0 and sign:
        raise ValueError('Sign')
    lhs = value+32768+2*sign*magnitude
    rhs = 32768+magnitude
    if (lhs-rhs) % P:
        raise ValueError('SourceSign')


def bind(record,value):
    equal_digits(record['result'],limbs.digits(value,8,max(1,(value.bit_length()+7)//8)))


def check_relations(p,supplied,xs,gs,w):
    c = validate(p,supplied)
    inputs(p,xs,gs)
    if (type(w) is not dict or set(w) != set(GLOBAL) | {'columns','rows'} or
            any(type(w[k]) is not int for k in GLOBAL) or type(w['columns']) is not dict or
            type(w['rows']) is not list or len(w['rows']) != p.d):
        raise ValueError('Witness')
    if not (-23 <= w['a'] <= 9 and 16384 <= w['M'] <= 65535 and 8192 <= w['J'] <= 16384):
        raise ValueError('Range')
    _,D,shift,divisor,_ = parameters(p,w)
    limits = dict(S=c['S_max'],N=c['N_max'],A=c['A_max'],MD=c['MD_max'],R=D-1)
    if any(not 0 <= w[k] <= limit for k,limit in limits.items()):
        raise ValueError('Range')
    if w['J'] != reciprocal(w['M']):
        raise ValueError('Table')
    limits = dict(x_magnitude=32768,x_sign=1,g_magnitude=32768,g_sign=1,product_sign=1,
                  xy=1 << 30,product=1 << 44,quotient=32768,
                  scaled_quotient=32768*c['round_divisor_max'],remainder=c['round_divisor_max']-1)
    for x,g,r in zip(xs,gs,w['rows']):
        if (type(r) is not dict or set(r) != set(ROW) | {'columns'} or
                any(type(r[k]) is not int for k in ROW) or type(r['columns']) is not dict):
            raise ValueError('Witness')
        if (any(not 0 <= r[k] <= limit for k,limit in limits.items()) or not -32768 <= r['output'] <= 32767):
            raise ValueError('Range')
        source_sign(x,r['x_magnitude'],r['x_sign'])
        source_sign(g,r['g_magnitude'],r['g_sign'])
        sign = (r['x_sign'] ^ r['g_sign']) if r['x_magnitude'] and r['g_magnitude'] else 0
        if r['product_sign'] != sign:
            raise ValueError('Sign')
        if shift < 0 and (r['remainder'] or r['scaled_quotient']):
            raise ValueError('Branch')
        if shift >= 0 and r['remainder'] >= divisor:
            raise ValueError('Range')
    global_values,rows = column_inputs(p,w)
    specs = column_specs(p)
    def columns(records,values):
        if records.keys() != values.keys():
            raise ValueError('Witness')
        for name,args in values.items():
            limbs.check_relations(specs[name],c['columns'][name],*args,records[name])
    # Bind each result before any later relation can consume a substituted value.
    if w['columns'].keys() != global_values.keys():
        raise ValueError('Witness')
    for name,target in [('statistic','S'),('numerator','N'),('scaled','A'),('normal_product','MD'),('normal_sum','A')]:
        record = w['columns'][name]
        limbs.check_relations(specs[name],c['columns'][name],*global_values[name],record)
        bind(record,w[target])
    for r,values in zip(w['rows'],rows):
        records = r['columns']
        columns(records,values)
        bind(records['xy'],r['xy']);bind(records['product'],r['product'])
        if shift < 0:
            bind(records['left'],r['quotient'])
        else:
            bind(records['quotient_product'],r['scaled_quotient'])
            equal_digits(records['bias']['result'],records['division']['result'])
        lhs = r['output']+32768+2*r['product_sign']*r['quotient']
        rhs = 32768+r['quotient']
        if (lhs-rhs) % P:
            raise ValueError('OutputRelation')
    return tuple(r['output'] for r in w['rows'])
