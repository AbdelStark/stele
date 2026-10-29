"""Q26 / Draft RFC-0004 A3/A8/A9: closed scaled-linear records, no proof consumer."""
from dataclasses import asdict, dataclass
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/scaled-linear/v1\0'
KINDS=('wide','gated','embedding')
BRANCHES=('right','left','zero_right','zero_only')
SCALARS=('acc_max','scale_min','scale_max','weighted_max','product_max','divisor','bias','left_factor','quotient_max','output_max')
FIELDS=('sign','magnitude','weighted','product','quotient','scaled_quotient','remainder','output')


@dataclass(frozen=True)
class Spec:
    kind: str
    dimension: int
    bits: int
    exponent: int
    input_fraction: int
    output_fraction: int
    mode: str
    scale: int


def constants(p):
    if (type(p) is not Spec or type(p.kind) is not str or p.kind not in KINDS or
            type(p.mode) is not str or p.mode not in ('dynamic','static') or
            any(type(getattr(p,k)) is not int for k in ('dimension','bits','exponent','input_fraction','output_fraction','scale')) or
            not 1<=p.dimension<=1<<20 or p.bits not in (4,8) or not -1099<=p.exponent<=1024 or
            not 0<=p.input_fraction<=(44 if p.kind=='gated' else 30) or not 0<=p.output_fraction<=30 or
            (p.mode=='dynamic' and p.scale!=0) or (p.mode=='static' and not 1<=p.scale<=65535)):
        raise ValueError('Spec')
    if p.kind=='embedding' and (p.dimension,p.input_fraction,p.mode,p.scale)!=(1,0,'static',1): raise ValueError('Spec')
    acc=p.dimension*((1<<(p.bits-1))-1)*(1 if p.kind=='embedding' else 127)
    if 2*acc>=P: raise ValueError('FieldBound')
    source_max=(1<<30) if p.kind=='gated' else 32768  # A8 product versus int16 wide row.
    scale=(source_max+126)//127 if p.mode=='dynamic' else p.scale
    product=acc*65535*scale; shift=p.input_fraction-p.exponent-p.output_fraction
    # A3/A8: Pmax<2^b. A right shift>b is below half a unit; a nonzero
    # magnitude shifted left by >=16 cannot be a signed-int16 result.
    if shift>product.bit_length(): branch='zero_right'
    elif shift>=0: branch='right'
    elif shift>=-15: branch='left'
    else: branch='zero_only'
    divisor=(1<<shift) if branch=='right' else 0
    bias=divisor//2 if shift>0 and branch=='right' else 0
    factor=(1<<-shift) if branch=='left' else 0
    quotient=min(32768,(product+bias)//divisor) if divisor else min(32768,product*factor)
    return dict(asdict(p),prime=P,radix_bits=8,shift=shift,branch=branch,acc_max=acc,
        scale_min=0 if p.mode=='dynamic' else scale,scale_max=scale,weighted_max=acc*65535,
        product_max=product,divisor=divisor,bias=bias,left_factor=factor,quotient_max=quotient,output_max=32768)


def column_specs(p):
    c=constants(p); spec=lambda a,b,count=1:limbs.Spec(count,a,b,8)
    columns=dict(weight_scale=spec(c['acc_max'],65535),row_scale=spec(c['weighted_max'],c['scale_max']))
    if c['branch']=='right':
        columns.update(bias=spec(max(c['product_max'],c['bias']),1,2),
            quotient_product=spec(c['quotient_max'],c['divisor']),
            division=spec(max(c['quotient_max']*c['divisor'],c['divisor']-1),1,2))
    if c['branch']=='left': columns['left']=spec(c['product_max'],c['left_factor'])
    return columns


def derive(p):
    c=constants(p)
    return dict(c,columns={k:limbs.derive(v) for k,v in column_specs(p).items()})


def validate(p,record):
    expected=derive(p)
    if not same(record,expected): raise ValueError('Certificate')
    return expected


def inputs(p,acc,mantissa,scale):
    c=constants(p)
    if (any(type(x) is not int for x in (acc,mantissa,scale)) or not -c['acc_max']<=acc<=c['acc_max'] or
            not 1<=mantissa<=65535 or not c['scale_min']<=scale<=c['scale_max']): raise ValueError('Input')
    if scale==0 and acc!=0: raise ValueError('ZeroScale')


def column_inputs(p,w,mantissa,scale):
    c=constants(p)
    values=dict(weight_scale=((w['magnitude'],),(mantissa,)),row_scale=((w['weighted'],),(scale,)))
    if c['branch']=='right': values.update(bias=((w['product'],c['bias']),(1,1)),
        quotient_product=((w['quotient'],),(c['divisor'],)),division=((w['scaled_quotient'],w['remainder']),(1,1)))
    if c['branch']=='left': values['left']=((w['product'],),(c['left_factor'],))
    return values


def attach(p,acc,mantissa,scale,w):
    """Build local columns; coherent substitutions still require the checker bindings."""
    inputs(p,acc,mantissa,scale); specs=column_specs(p)
    w['columns']={k:limbs.witness(specs[k],*v) for k,v in column_inputs(p,w,mantissa,scale).items()}
    return w


def witness(p,acc,mantissa,scale):
    c=derive(p); inputs(p,acc,mantissa,scale)
    weighted=abs(acc)*mantissa; product=weighted*scale; q=r=0
    if c['branch']=='right': q,r=divmod(product+c['bias'],c['divisor'])
    elif c['branch']=='left': q=product*c['left_factor']
    elif c['branch']=='zero_only' and product: raise ValueError('OutputRange')
    output=-q if acc<0 else q
    if not -32768<=output<=32767: raise ValueError('OutputRange')
    w=dict(sign=int(acc<0),magnitude=abs(acc),weighted=weighted,product=product,quotient=q,
           scaled_quotient=q*c['divisor'],remainder=r,output=output)
    return attach(p,acc,mantissa,scale,w)


def check_relations(p,record,acc,mantissa,scale,w):
    """Plaintext range/source model: no authentication of the dot, scale or weights."""
    c=validate(p,record); inputs(p,acc,mantissa,scale)
    if (type(w) is not dict or set(w)!=set(FIELDS)|{'columns'} or
            any(type(w[k]) is not int for k in FIELDS) or type(w['columns']) is not dict or
            w['columns'].keys()!=c['columns'].keys()): raise ValueError('Witness')
    bounds=dict(sign=1,magnitude=c['acc_max'],weighted=c['weighted_max'],product=c['product_max'],
        quotient=c['quotient_max'],scaled_quotient=c['quotient_max']*c['divisor'],remainder=max(0,c['divisor']-1))
    if any(not 0<=w[k]<=v for k,v in bounds.items()) or not -32768<=w['output']<=32767: raise ValueError('Range')
    if w['magnitude']==0 and w['sign']: raise ValueError('Sign')
    # Boolean sign bounds the entire signed expression by acc_max on either side.
    if (acc-(1-2*w['sign'])*w['magnitude'])%P: raise ValueError('SourceSign')
    if c['branch']=='zero_only' and w['product']: raise ValueError('ZeroOnly')
    values=column_inputs(p,w,mantissa,scale)
    for k,spec in column_specs(p).items(): limbs.check_relations(spec,c['columns'][k],*values[k],w['columns'][k])
    def bind(role,value): equal_digits(w['columns'][role]['result'],limbs.digits(value,8,max(1,(value.bit_length()+7)//8)))
    bind('weight_scale',w['weighted']); bind('row_scale',w['product'])
    if c['branch']=='right':
        bind('quotient_product',w['scaled_quotient']); equal_digits(w['columns']['bias']['result'],w['columns']['division']['result'])
    if c['branch']=='left': bind('left',w['quotient'])
    if (w['output']-(1-2*w['sign'])*w['quotient'])%P: raise ValueError('OutputRelation')
    return w['output']


def encode(p):
    c=derive(p)
    raw=TAG+bytes([KINDS.index(p.kind)])+unsigned(p.dimension,4)+bytes([p.bits])+p.exponent.to_bytes(2,'little',signed=True)
    raw+=bytes([p.input_fraction,p.output_fraction,('dynamic','static').index(p.mode)])+unsigned(p.scale,2)
    raw+=unsigned(P,4)+bytes([8,BRANCHES.index(c['branch'])])+c['shift'].to_bytes(2,'little',signed=True)+bytes([len(SCALARS)])
    raw+=b''.join(unsigned(c[k],20) for k in SCALARS)+bytes([len(c['columns'])])
    for i,record in enumerate(c['columns'].values(),1):
        raw+=bytes([i])+unsigned(record['count'],4)
        raw+=b''.join(unsigned(record[k],20) for k in ('left_max','right_max','result_max'))
        raw+=bytes([len(record[k]) for k in ('left_caps','right_caps','result_caps')])
        raw+=b''.join(bytes(record[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(unsigned(v,4) for k in ('carry_caps','lhs','rhs') for v in record[k])
    if len(raw)>2048: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>2048 or raw!=expected: raise ValueError('Encoding')
