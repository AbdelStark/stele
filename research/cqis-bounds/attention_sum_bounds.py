"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: signed attention sums, no proof consumer."""
from dataclasses import asdict, dataclass
import bounded_columns as columns
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/attention-sum-bounds/v1\0'
SCALARS=('term_cap','probability_max','code_max','scale_min','scale_max','restored_max','value_offset_max',
         'weight_sum_max','base_max','offset_sum_max','magnitude_max','source_rhs_max','entry_capacity','block_max')


@dataclass(frozen=True)
class Spec:
    length: int
    width: int
    fraction: int
    exponent: int
    value_mode: str
    scale: int
    accumulation: str


def constants(p):
    if (type(p) is not Spec or any(type(getattr(p,k)) is not int for k in ('length','width','fraction','exponent','scale')) or
            type(p.value_mode) is not str or p.value_mode not in ('dynamic','static') or
            type(p.accumulation) is not str or p.accumulation not in ('exact','block1024') or
            not 1<=p.length<=1<<20 or not 1<=p.width<=16384 or not 0<=p.fraction<=30 or not 0<=p.exponent<=14 or
            (p.scale!=0 if p.value_mode=='dynamic' else not 1<=p.scale<=65535)): raise ValueError('Spec')
    count=p.length if p.accumulation=='exact' else min(1024,p.length)
    code=127 if p.value_mode=='dynamic' else min(127,(65536+p.scale)//(2*p.scale))
    scale=259 if p.value_mode=='dynamic' else p.scale; s=code*scale; probability=1<<p.exponent
    z=count*probability; h=z*s
    return dict(asdict(p),prime=P,term_cap=count,probability_max=probability,code_max=code,
                scale_min=0 if p.value_mode=='dynamic' else scale,scale_max=scale,restored_max=s,
                value_offset_max=2*s,weight_sum_max=z,base_max=h,offset_sum_max=2*h,magnitude_max=h,
                source_rhs_max=2*s,entry_capacity=1<<20,block_max=(p.length-1)//1024 if p.accumulation=='block1024' else 0)


def column_specs(p):
    c=constants(p); n=c['term_cap']; a=c['probability_max']; s=c['restored_max']; z=c['weight_sum_max']; h=c['base_max']
    return dict(shared_columns=dict(weight_sum=limbs.Spec(n,a,1,4),base=limbs.Spec(1,z,s,4)),
                entry_columns=dict(offset_sum=limbs.Spec(n,a,2*s,4),sign_lhs=limbs.Spec(2,2*h,2,4),
                                   sign_rhs=limbs.Spec(2,h,1,4),sign_gap=limbs.Spec(2,h,1,4)))


def derive(p):
    c=constants(p)
    if 2*c['source_rhs_max']>=P: raise ValueError('FieldBound')
    return dict(c,**{group:{name:limbs.derive(s) for name,s in specs.items()} for group,specs in column_specs(p).items()})


def validate(p,record):
    c=derive(p)
    if not same(record,c): raise ValueError('Certificate')
    return c


def inputs(p,positions,block,weights,codes,scales,allowed):
    c=constants(p)
    if (type(positions) is not tuple or not 1<=len(positions)<=c['term_cap'] or len(positions)*p.width>c['entry_capacity'] or
            any(type(v) is not int or not 0<=v<p.length for v in positions) or
            any(x>=y for x,y in zip(positions,positions[1:]))): raise ValueError('Positions')
    n=len(positions)
    if (type(block) is not int or not 0<=block<=c['block_max'] or
            (p.accumulation=='block1024' and any(v//1024!=block for v in positions))): raise ValueError('Block')
    if type(allowed) is not tuple or len(allowed)!=n or any(type(v) is not bool for v in allowed): raise ValueError('Mask')
    if type(weights) is not tuple or len(weights)!=n or any(type(v) is not int or not 0<=v<=c['probability_max'] for v in weights):
        raise ValueError('Weights')
    if any(w and not bit for w,bit in zip(weights,allowed)): raise ValueError('MaskWeight')
    if type(scales) is not tuple or len(scales)!=n or any(type(v) is not int or not c['scale_min']<=v<=c['scale_max'] for v in scales):
        raise ValueError('Scale')
    if (type(codes) is not tuple or len(codes)!=n or any(type(row) is not tuple or len(row)!=p.width or
            any(type(v) is not int or abs(v)>c['code_max'] for v in row) for row in codes)): raise ValueError('Codes')
    if any(s==0 and any(row) for s,row in zip(scales,codes)): raise ValueError('ZeroScale')


def column_inputs(p,weights,w):
    c=constants(p)
    shared=dict(weight_sum=(weights,(1,)*len(weights)),base=((w['weight_sum'],),(c['restored_max'],)))
    entries=[]
    for j,e in enumerate(w['entries']):
        entries.append(dict(offset_sum=(weights,tuple(row[j] for row in w['offsets'])),
                            sign_lhs=((e['offset_sum'],e['magnitude']),(1,2*e['sign'])),
                            sign_rhs=((w['base'],e['magnitude']),(1,1)),sign_gap=((e['gap'],e['sign']),(1,1))))
    return shared,entries


def attach(p,positions,block,weights,codes,scales,allowed,w):
    specs=column_specs(p); shared,entries=column_inputs(p,weights,w)
    w['columns']={name:columns.witness(s,*shared[name]) for name,s in specs['shared_columns'].items()}
    for e,values in zip(w['entries'],entries):
        e['columns']={name:columns.witness(s,*values[name]) for name,s in specs['entry_columns'].items()}
    return w


def witness(p,positions,block,weights,codes,scales,allowed):
    c=derive(p); inputs(p,positions,block,weights,codes,scales,allowed); z=sum(weights); base=z*c['restored_max']
    offsets=tuple(tuple(c['restored_max']+v*s for v in row) for row,s in zip(codes,scales)); entries=[]
    for j in range(p.width):
        offset=sum(w*row[j] for w,row in zip(weights,offsets)); total=offset-base; b=int(total<0); a=abs(total)
        entries.append(dict(offset_sum=offset,sign=b,magnitude=a,gap=a-b))
    w=dict(positions=positions,block=block,offsets=offsets,weight_sum=z,base=base,entries=tuple(entries))
    return attach(p,positions,block,weights,codes,scales,allowed,w)


def check_relations(p,record,positions,block,weights,codes,scales,allowed,w):
    """Conditional plaintext sources; wide equalities use canonical digits, including zero sums."""
    c=validate(p,record); inputs(p,positions,block,weights,codes,scales,allowed); specs=column_specs(p); n=len(positions)
    if (type(w) is not dict or set(w)!={'positions','block','offsets','weight_sum','base','columns','entries'} or
            type(w['entries']) is not tuple or len(w['entries'])!=p.width or type(w['columns']) is not dict or
            w['columns'].keys()!=specs['shared_columns'].keys()): raise ValueError('Witness')
    if type(w['positions']) is not tuple or any(type(v) is not int for v in w['positions']) or w['positions']!=positions: raise ValueError('Positions')
    if type(w['block']) is not int or w['block']!=block: raise ValueError('Block')
    if any(type(w[k]) is not int or not 0<=w[k]<=c[limit] for k,limit in (('weight_sum','weight_sum_max'),('base','base_max'))): raise ValueError('Range')
    if (type(w['offsets']) is not tuple or len(w['offsets'])!=n or any(type(row) is not tuple or len(row)!=p.width or
            any(type(v) is not int for v in row) for row in w['offsets'])): raise ValueError('Witness')
    for offsets,row,scale in zip(w['offsets'],codes,scales):
        for u,code in zip(offsets,row):
            if not 0<=u<=c['value_offset_max']: raise ValueError('Range')
            if (u-c['restored_max']-code*scale)%P: raise ValueError('SourceValue')
    bounds=dict(offset_sum=c['offset_sum_max'],sign=1,magnitude=c['magnitude_max'],gap=c['magnitude_max'])
    for e in w['entries']:
        if (type(e) is not dict or set(e)!=set(bounds)|{'columns'} or any(type(e[k]) is not int for k in bounds) or
                type(e['columns']) is not dict or e['columns'].keys()!=specs['entry_columns'].keys()): raise ValueError('Witness')
        if any(not 0<=e[k]<=v for k,v in bounds.items()): raise ValueError('Range')
    shared,entries=column_inputs(p,weights,w)
    for name,s in specs['shared_columns'].items(): columns.check_relations(s,c['shared_columns'][name],*shared[name],w['columns'][name])
    def digits(v): return limbs.digits(v,4,14)
    for name in ('weight_sum','base'): equal_digits(w['columns'][name]['result'],digits(w[name]))
    for e,values in zip(w['entries'],entries):
        cols=e['columns']
        for name,s in specs['entry_columns'].items(): columns.check_relations(s,c['entry_columns'][name],*values[name],cols[name])
        equal_digits(cols['offset_sum']['result'],digits(e['offset_sum']))
        equal_digits(cols['sign_lhs']['result'],cols['sign_rhs']['result'])
        equal_digits(cols['sign_gap']['result'],digits(e['magnitude']))
    return w['weight_sum'],tuple((1-2*e['sign'])*e['magnitude'] for e in w['entries'])


def encode(p):
    c=derive(p); raw=TAG+unsigned(p.length,4)+unsigned(p.width,2)
    raw+=bytes([p.fraction,p.exponent,('dynamic','static').index(p.value_mode)])+unsigned(p.scale,2)
    raw+=bytes([('exact','block1024').index(p.accumulation)])+unsigned(P,4)+bytes([4,len(SCALARS)])
    raw+=b''.join(unsigned(c[k],20) for k in SCALARS)
    for group in ('shared_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,rec in enumerate(c[group].values(),1):
            raw+=bytes([i])+unsigned(rec['count'],4)+b''.join(unsigned(rec[k],20) for k in ('left_max','right_max','result_max'))
            raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(unsigned(v,4) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    if len(raw)>2048: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>2048 or raw!=expected: raise ValueError('Encoding')
