"""Q26 / Draft RFC-0004 A3/A8: exact gated products, no source/range proof consumer."""
from dataclasses import asdict, dataclass
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/gated-product-bounds/v1\0'
SCALARS=('product_fraction','source_max','source_high','source_offset_max','output_max','output_offset_max',
         'offset_product_max','offset_bias','restoration_factor','entry_capacity')


@dataclass(frozen=True)
class Spec:
    dimension: int
    up_fraction: int
    silu_fraction: int


def constants(p):
    if (type(p) is not Spec or any(type(v) is not int for v in asdict(p).values()) or not 1<=p.dimension<=16384 or
            not 0<=p.up_fraction<=30 or not 0<=p.silu_fraction<=14): raise ValueError('Spec')
    return dict(asdict(p),prime=P,product_fraction=p.up_fraction+p.silu_fraction,source_max=32768,source_high=32767,
                source_offset_max=65535,output_max=1<<30,output_offset_max=1<<31,offset_product_max=65535**2,
                offset_bias=1<<31,restoration_factor=32768,entry_capacity=16384)


def column_specs(p):
    c=constants(p)
    return dict(product=limbs.Spec(1,c['source_offset_max'],c['source_offset_max'],8),
                lhs=limbs.Spec(2,c['offset_product_max'],1,8),rhs=limbs.Spec(3,c['output_offset_max'],c['restoration_factor'],8))


def derive(p):
    return dict(constants(p),columns={name:limbs.derive(s) for name,s in column_specs(p).items()})


def validate(p,record):
    c=derive(p)
    if not same(record,c): raise ValueError('Certificate')
    return c


def inputs(p,xs,ys):
    constants(p)
    if any(type(row) is not tuple or len(row)!=p.dimension or
           any(type(v) is not int or not -32768<=v<=32767 for v in row) for row in (xs,ys)): raise ValueError('Input')


def column_inputs(p,xs,ys,w):
    c=constants(p)
    return [dict(product=((x+c['source_max'],),(y+c['source_max'],)),
                 lhs=((e['offset_product'],c['offset_bias']),(1,1)),
                 rhs=((e['output']+c['output_max'],x+c['source_max'],y+c['source_max']),(1,c['restoration_factor'],c['restoration_factor'])))
            for x,y,e in zip(xs,ys,w['entries'])]


def attach(p,xs,ys,w):
    specs=column_specs(p)
    for e,values in zip(w['entries'],column_inputs(p,xs,ys,w)):
        e['columns']={name:limbs.witness(s,*values[name]) for name,s in specs.items()}
    return w


def witness(p,xs,ys):
    derive(p); inputs(p,xs,ys)
    entries=tuple(dict(offset_product=(x+32768)*(y+32768),output=x*y) for x,y in zip(xs,ys))
    return attach(p,xs,ys,dict(entries=entries))


def check_relations(p,record,xs,ys,w):
    """uv+2^31=(output+2^30)+32768u+32768v is checked as an integer through byte columns."""
    c=validate(p,record); inputs(p,xs,ys); specs=column_specs(p)
    if type(w) is not dict or set(w)!={'entries'} or type(w['entries']) is not tuple or len(w['entries'])!=p.dimension:
        raise ValueError('Witness')
    for e in w['entries']:
        if (type(e) is not dict or set(e)!={'offset_product','output','columns'} or type(e['offset_product']) is not int or
                type(e['output']) is not int or type(e['columns']) is not dict or e['columns'].keys()!=specs.keys()): raise ValueError('Witness')
        if not 0<=e['offset_product']<=c['offset_product_max'] or abs(e['output'])>c['output_max']: raise ValueError('Range')
    for e,values in zip(w['entries'],column_inputs(p,xs,ys,w)):
        cols=e['columns']
        for name,s in specs.items(): limbs.check_relations(s,c['columns'][name],*values[name],cols[name])
        equal_digits(cols['product']['result'],limbs.digits(e['offset_product'],8,8))
        equal_digits(cols['lhs']['result'],cols['rhs']['result'])
    return tuple(e['output'] for e in w['entries'])


def encode(p):
    c=derive(p); raw=TAG+unsigned(p.dimension,4)+bytes([p.up_fraction,p.silu_fraction])
    raw+=unsigned(P,4)+bytes([8,len(SCALARS)])+b''.join(c[k].to_bytes(8,'little') for k in SCALARS)+bytes([len(c['columns'])])
    for i,rec in enumerate(c['columns'].values(),1):
        raw+=bytes([i])+unsigned(rec['count'],4)+b''.join(rec[k].to_bytes(8,'little') for k in ('left_max','right_max','result_max'))
        raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(unsigned(v,4) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    if len(raw)>512: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>512 or raw!=expected: raise ValueError('Encoding')
