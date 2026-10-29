"""Q26 / Draft RFC-0004 A3/A8: static one-round residual columns, no proof consumer."""
from dataclasses import asdict, dataclass
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/residual-bounds/v1\0'
SCALARS=('source_max','source_high','left_factor','right_factor','divisor','bias','numerator_max',
         'offset_max','quotient_max','scaled_quotient_max','remainder_max','output_max')
FIELDS=('offset','sign','magnitude','sign_gap','quotient','scaled_quotient','remainder','output')


@dataclass(frozen=True)
class Spec:
    dimension: int
    left_fraction: int
    right_fraction: int
    output_fraction: int


def constants(p):
    if (type(p) is not Spec or any(type(v) is not int for v in asdict(p).values()) or
            not 1<=p.dimension<=1<<20 or any(not 0<=f<=30 for f in (p.left_fraction,p.right_fraction,p.output_fraction))):
        raise ValueError('Spec')
    common=max(p.left_fraction,p.right_fraction,p.output_fraction)
    a=1<<(common-p.left_fraction); b=1<<(common-p.right_fraction); d=1<<(common-p.output_fraction)
    return dict(asdict(p),prime=P,source_max=32768,source_high=32767,left_factor=a,right_factor=b,
                divisor=d,bias=d//2,numerator_max=32768*(a+b),offset_max=65535*(a+b),quotient_max=32768,
                scaled_quotient_max=32768*d,remainder_max=d-1,output_max=32768)


def column_specs(p):
    c=constants(p); n=c['numerator_max']; d=c['divisor']
    return dict(aligned=limbs.Spec(2,65535,max(c['left_factor'],c['right_factor']),8),
                sign_lhs=limbs.Spec(2,c['offset_max'],2,8),sign_rhs=limbs.Spec(2,n,1,8),
                sign_gap=limbs.Spec(2,n,1,8),bias=limbs.Spec(2,max(n,c['bias']),1,8),
                quotient_product=limbs.Spec(1,32768,d,8),division=limbs.Spec(2,max(32768*d,d-1),1,8))


def derive(p):
    c=constants(p)
    if 2*c['output_max']>=P: raise ValueError('FieldBound')
    return dict(c,columns={name:limbs.derive(s) for name,s in column_specs(p).items()})


def validate(p,record):
    expected=derive(p)
    if not same(record,expected): raise ValueError('Certificate')
    return expected


def inputs(p,xs,ys):
    constants(p)
    if any(type(row) is not tuple or len(row)!=p.dimension or
           any(type(v) is not int or not -32768<=v<=32767 for v in row) for row in (xs,ys)): raise ValueError('Input')


def column_inputs(p,x,y,e):
    c=constants(p)
    return dict(aligned=((x+32768,y+32768),(c['left_factor'],c['right_factor'])),
                sign_lhs=((e['offset'],e['magnitude']),(1,2*e['sign'])),
                sign_rhs=((c['numerator_max'],e['magnitude']),(1,1)),
                sign_gap=((e['sign_gap'],e['sign']),(1,1)),
                bias=((e['magnitude'],c['bias']),(1,1)),
                quotient_product=((e['quotient'],),(c['divisor'],)),
                division=((e['scaled_quotient'],e['remainder']),(1,1)))


def attach(p,xs,ys,w):
    specs=column_specs(p)
    for x,y,e in zip(xs,ys,w['entries']):
        values=column_inputs(p,x,y,e)
        e['columns']={name:limbs.witness(s,*values[name]) for name,s in specs.items()}
    return w


def witness(p,xs,ys):
    c=derive(p); inputs(p,xs,ys); entries=[]
    for x,y in zip(xs,ys):
        total=x*c['left_factor']+y*c['right_factor']; sign=int(total<0); magnitude=abs(total)
        q,remainder=divmod(magnitude+c['bias'],c['divisor']); output=-q if sign else q
        if not -32768<=output<=32767: raise ValueError('OutputRange')
        entries.append(dict(offset=total+c['numerator_max'],sign=sign,magnitude=magnitude,
                            sign_gap=magnitude-sign,quotient=q,scaled_quotient=q*c['divisor'],
                            remainder=remainder,output=output))
    return attach(p,xs,ys,dict(entries=tuple(entries)))


def check_relations(p,record,xs,ys,w):
    """Plaintext whole sources/ranges; every wide equality is canonical digit equality."""
    c=validate(p,record); inputs(p,xs,ys); specs=column_specs(p)
    if type(w) is not dict or set(w)!={'entries'} or type(w['entries']) is not tuple or len(w['entries'])!=p.dimension:
        raise ValueError('Witness')
    bounds=dict(offset=c['offset_max'],sign=1,magnitude=c['numerator_max'],sign_gap=c['numerator_max'],
                quotient=32768,scaled_quotient=c['scaled_quotient_max'],remainder=c['remainder_max'])
    def digits(v): return limbs.digits(v,8,7)
    for x,y,e in zip(xs,ys,w['entries']):
        if (type(e) is not dict or set(e)!=set(FIELDS)|{'columns'} or any(type(e[k]) is not int for k in FIELDS) or
                type(e['columns']) is not dict or e['columns'].keys()!=specs.keys()): raise ValueError('Witness')
        if any(not 0<=e[k]<=v for k,v in bounds.items()) or not -32768<=e['output']<=32767: raise ValueError('Range')
        values=column_inputs(p,x,y,e); cols=e['columns']
        for name,s in specs.items(): limbs.check_relations(s,c['columns'][name],*values[name],cols[name])
        equal_digits(cols['aligned']['result'],digits(e['offset']))
        equal_digits(cols['sign_lhs']['result'],cols['sign_rhs']['result'])
        equal_digits(cols['sign_gap']['result'],digits(e['magnitude']))
        equal_digits(cols['quotient_product']['result'],digits(e['scaled_quotient']))
        equal_digits(cols['bias']['result'],cols['division']['result'])
        # Only this signed output identity uses a direct small field equality.
        if (e['output']-(1-2*e['sign'])*e['quotient'])%P: raise ValueError('OutputRelation')
    return tuple(e['output'] for e in w['entries'])


def encode(p):
    c=derive(p); raw=TAG+unsigned(p.dimension,4)+bytes([p.left_fraction,p.right_fraction,p.output_fraction])
    raw+=unsigned(P,4)+bytes([8,len(SCALARS)])+b''.join(unsigned(c[k],20) for k in SCALARS)
    raw+=bytes([len(c['columns'])])
    for i,record in enumerate(c['columns'].values(),1):
        raw+=bytes([i])+unsigned(record['count'],4)
        raw+=b''.join(unsigned(record[k],20) for k in ('left_max','right_max','result_max'))
        raw+=bytes(len(record[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(bytes(record[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(unsigned(v,4) for k in ('carry_caps','lhs','rhs') for v in record[k])
    if len(raw)>2048: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>2048 or raw!=expected: raise ValueError('Encoding')
