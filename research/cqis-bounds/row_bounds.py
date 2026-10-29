"""Q26 / Draft RFC-0004 A3/A8: closed row arithmetic, no proof consumers."""
from dataclasses import asdict, dataclass
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/row-bounds/v1\0'
SCALARS=('source_max','source_high','offset_max','scale_min','scale_max','predecessor_max',
         'maximum_max','selected_max','slack_max','gap_max','quotient_max','scaled_quotient_max',
         'remainder_max','scale_bound','remainder_lhs_bound','remainder_rhs_bound',
         'zero_lhs_bound','zero_rhs_bound','output_bound')
ROW_FIELDS=('scale','nonzero','predecessor','maximum','selected','slack')
ENTRY_FIELDS=('sign','magnitude','gap','quotient','scaled_quotient','remainder','remainder_gap','zero_gap','code')


@dataclass(frozen=True)
class Spec:
    kind: str
    dimension: int
    fraction: int
    mode: str
    scale: int


def constants(p):
    if (type(p) is not Spec or type(p.kind) is not str or p.kind not in ('wide','gated') or
            type(p.mode) is not str or p.mode not in ('dynamic','static') or
            any(type(getattr(p,k)) is not int for k in ('dimension','fraction','scale')) or
            not 1<=p.dimension<=1<<20 or not 0<=p.fraction<=(44 if p.kind=='gated' else 30) or
            (p.mode=='dynamic' and p.scale!=0) or (p.mode=='static' and not 1<=p.scale<=65535)):
        raise ValueError('Spec')
    dynamic=p.mode=='dynamic'; bound=(1<<30) if p.kind=='gated' else 32768
    high=bound if p.kind=='gated' else bound-1
    scale=(bound+126)//127 if dynamic else p.scale
    c=dict(asdict(p),prime=P,radix_bits=8,source_max=bound,source_high=high,offset_max=bound+high,
           scale_min=0 if dynamic else scale,scale_max=scale,predecessor_max=scale-1,
           maximum_max=bound if dynamic else 0,selected_max=p.dimension-1 if dynamic else 0,
           slack_max=126 if dynamic else 0,gap_max=bound if dynamic else 0,quotient_max=127,
           scaled_quotient_max=254*scale,remainder_max=2*scale-1,scale_bound=scale,
           remainder_lhs_bound=4*scale-1,remainder_rhs_bound=2*scale,
           zero_lhs_bound=254,zero_rhs_bound=127,output_bound=127)
    if any(2*c[k]>=P for k in SCALARS if k.endswith('_bound')): raise ValueError('FieldBound')
    return c


def column_specs(p):
    c=constants(p); spec=lambda a,b,count=1:limbs.Spec(count,a,b,8)
    row=dict(scale_product=spec(c['scale_max'],127),scale_ceiling=spec(c['source_max'],1,2)) if p.mode=='dynamic' else {}
    entry=dict(input_lhs=spec(c['offset_max'],2,2),input_rhs=spec(c['source_max'],1,2))
    if p.mode=='dynamic': entry['max_gap']=spec(c['source_max'],1,2)
    entry.update(rounding=spec(max(c['source_max'],c['scale_max']),2,2),
                 quotient_product=spec(127,2*c['scale_max']),
                 division=spec(c['scaled_quotient_max'],1,2))
    return dict(row_columns=row,entry_columns=entry)


def derive(p):
    return dict(constants(p),**{group:{name:limbs.derive(s) for name,s in specs.items()}
                               for group,specs in column_specs(p).items()})


def validate(p,record):
    expected=derive(p)
    if not same(record,expected): raise ValueError('Certificate')
    return expected


def inputs(p,xs):
    c=constants(p)
    if (type(xs) is not tuple or len(xs)!=p.dimension or
            any(type(x) is not int or not -c['source_max']<=x<=c['source_high'] for x in xs)):
        raise ValueError('Input')


def row_inputs(p,w):
    return dict(scale_product=((w['scale'],),(127,)),scale_ceiling=((w['maximum'],w['slack']),(1,1))) if p.mode=='dynamic' else {}


def entry_inputs(p,w,x,e):
    c=constants(p)
    values=dict(input_lhs=((x+c['source_max'],e['magnitude']),(1,2*e['sign'])),
                input_rhs=((c['source_max'],e['magnitude']),(1,1)))
    if p.mode=='dynamic': values['max_gap']=((e['magnitude'],e['gap']),(1,1))
    values.update(rounding=((e['magnitude'],w['scale']),(2,1)),
                  quotient_product=((e['quotient'],),(2*w['scale'],)),
                  division=((e['scaled_quotient'],e['remainder']),(1,1)))
    return values


def attach(p,xs,w):
    """Build local columns; this does not establish the bindings between them."""
    inputs(p,xs); specs=column_specs(p)
    w['columns']={name:limbs.witness(specs['row_columns'][name],*v) for name,v in row_inputs(p,w).items()}
    for x,e in zip(xs,w['entries']):
        e['columns']={name:limbs.witness(specs['entry_columns'][name],*v) for name,v in entry_inputs(p,w,x,e).items()}
    return w


def witness(p,xs):
    derive(p); inputs(p,xs); maximum=max(map(abs,xs)) if p.mode=='dynamic' else 0
    scale=(maximum+126)//127 if p.mode=='dynamic' else p.scale; nonzero=int(scale!=0)
    selected=next(i for i,x in enumerate(xs) if abs(x)==maximum) if p.mode=='dynamic' else 0
    w=dict(scale=scale,nonzero=nonzero,predecessor=scale-1 if nonzero else 0,maximum=maximum,
           selected=selected,slack=127*scale-maximum if p.mode=='dynamic' else 0,entries=())
    entries=[]
    for x in xs:
        magnitude=abs(x); q,remainder=divmod(2*magnitude+scale,2*scale) if scale else (0,0)
        if q>127: raise ValueError('OutputRange')
        entries.append(dict(sign=int(x<0),magnitude=magnitude,gap=maximum-magnitude if p.mode=='dynamic' else 0,
            quotient=q,scaled_quotient=2*q*scale,remainder=remainder,remainder_gap=2*scale-nonzero-remainder,
            zero_gap=127*nonzero-q,code=-q if x<0 else q))
    w['entries']=tuple(entries)
    return attach(p,xs,w)


def check_relations(p,record,xs,w):
    """Plaintext expected sources/ranges/selection; no authenticated inference proof."""
    c=validate(p,record); inputs(p,xs); specs=column_specs(p)
    def shape(value,fields,columns,extra=()):
        if (type(value) is not dict or set(value)!=set(fields)|{'columns'}|set(extra) or
                any(type(value[k]) is not int for k in fields) or type(value['columns']) is not dict or
                value['columns'].keys()!=columns.keys()): raise ValueError('Witness')
    shape(w,ROW_FIELDS,c['row_columns'],('entries',))
    if type(w['entries']) is not tuple or len(w['entries'])!=p.dimension: raise ValueError('Witness')
    bounds=dict(nonzero=1,predecessor=c['predecessor_max'],maximum=c['maximum_max'],
                selected=c['selected_max'],slack=c['slack_max'])
    if any(not 0<=w[k]<=v for k,v in bounds.items()) or not c['scale_min']<=w['scale']<=c['scale_max']: raise ValueError('Range')
    # A3 zero semantics: bounded predecessor makes nonzero equivalent to scale>0.
    if (w['scale']-w['nonzero']*(w['predecessor']+1))%P: raise ValueError('ScaleRelation')
    if (1-w['nonzero'])*w['predecessor']%P: raise ValueError('ScaleCanonical')
    def check_columns(group,columns,values):
        for name,spec in specs[group].items(): limbs.check_relations(spec,c[group][name],*values[name],columns[name])
    def digits(value): return limbs.digits(value,8,5)
    check_columns('row_columns',w['columns'],row_inputs(p,w))
    if p.mode=='dynamic': equal_digits(w['columns']['scale_product']['result'],w['columns']['scale_ceiling']['result'])
    bounds=dict(sign=1,magnitude=c['source_max'],gap=c['gap_max'],quotient=127,
                scaled_quotient=c['scaled_quotient_max'],remainder=c['remainder_max'],
                remainder_gap=c['remainder_max'],zero_gap=127)
    for x,e in zip(xs,w['entries']):
        shape(e,ENTRY_FIELDS,c['entry_columns'])
        if any(not 0<=e[k]<=v for k,v in bounds.items()) or not -127<=e['code']<=127: raise ValueError('Range')
        if e['magnitude']==0 and e['sign']: raise ValueError('Sign')
        # Uniform, statically bounded identities also constrain the all-zero row.
        if (e['quotient']+e['zero_gap']-127*w['nonzero'])%P: raise ValueError('ZeroCode')
        if (e['remainder']+e['remainder_gap']+w['nonzero']-2*w['scale'])%P: raise ValueError('Remainder')
        check_columns('entry_columns',e['columns'],entry_inputs(p,w,x,e)); cols=e['columns']
        equal_digits(cols['input_lhs']['result'],cols['input_rhs']['result'])
        if p.mode=='dynamic': equal_digits(cols['max_gap']['result'],digits(w['maximum']))
        equal_digits(cols['quotient_product']['result'],digits(e['scaled_quotient']))
        equal_digits(cols['rounding']['result'],cols['division']['result'])
        if (e['code']-(1-2*e['sign'])*e['quotient'])%P: raise ValueError('OutputRelation')
    if p.mode=='dynamic' and digits(w['entries'][w['selected']]['magnitude'])!=digits(w['maximum']): raise ValueError('Attainment')
    return w['scale'],tuple(e['code'] for e in w['entries'])


def encode(p):
    c=derive(p)
    raw=TAG+bytes([('wide','gated').index(p.kind)])+unsigned(p.dimension,4)
    raw+=bytes([p.fraction,('dynamic','static').index(p.mode)])+unsigned(p.scale,2)
    raw+=unsigned(P,4)+bytes([8,len(SCALARS)])+b''.join(unsigned(c[k],20) for k in SCALARS)
    for group in ('row_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,record in enumerate(c[group].values(),1):
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
