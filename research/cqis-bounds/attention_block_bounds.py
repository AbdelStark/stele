"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: block rounding and sums, no proof consumer."""
from dataclasses import asdict, dataclass
import attention_sum_bounds as sums
import bounded_columns as bounded
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/attention-block-bounds/v1\0'
SCALARS=('probability_max','restored_max','block_count_max','block_id_max','raw_max','source_offset_max',
         'divisor','bias','rounded_max','scaled_quotient_max','remainder_max','total_max','sum_side_max',
         'block_z_max','z_max','entry_capacity')


@dataclass(frozen=True)
class Spec:
    length: int
    width: int
    fraction: int
    exponent: int
    value_mode: str
    scale: int
    drop: int


def constants(p):
    if type(p) is not Spec or type(p.drop) is not int or not 0<=p.drop<=62: raise ValueError('Spec')
    c=sums.constants(sums.Spec(p.length,p.width,p.fraction,p.exponent,p.value_mode,p.scale,'block1024'))
    probability=c['probability_max']; s=c['restored_max']; blocks=(p.length+1023)//1024
    h=1024*probability*s; d=1<<p.drop; q=(h+d//2)//d
    if q>32767: raise ValueError('BlockBound')
    total=blocks*q
    return dict(asdict(p),prime=P,probability_max=probability,restored_max=s,block_count_max=blocks,
                block_id_max=blocks-1,raw_max=h,source_offset_max=2*h,divisor=d,bias=d//2,rounded_max=q,
                scaled_quotient_max=q*d,remainder_max=d-1,total_max=total,sum_side_max=total,
                block_z_max=1024*probability,z_max=p.length*probability,entry_capacity=1<<20)


def column_specs(p):
    c=constants(p); h=c['raw_max']; d=c['divisor']; q=c['rounded_max']
    return dict(shared_columns=dict(probability_sum=limbs.Spec(c['block_count_max'],c['block_z_max'],1,8)),
                entry_columns=dict(sign_lhs=limbs.Spec(2,2*h,2,8),sign_rhs=limbs.Spec(2,h,1,8),sign_gap=limbs.Spec(2,h,1,8),
                                   bias=limbs.Spec(2,max(h,c['bias']),1,8),quotient_product=limbs.Spec(1,q,d,8),
                                   division=limbs.Spec(2,max(q*d,d-1),1,8)))


def derive(p):
    c=constants(p)
    if 2*c['sum_side_max']>=P: raise ValueError('FieldBound')
    return dict(c,**{group:{name:limbs.derive(s) for name,s in specs.items()} for group,specs in column_specs(p).items()})


def validate(p,record):
    c=derive(p)
    if not same(record,c): raise ValueError('Certificate')
    return c


def inputs(p,ids,zs,raw):
    c=constants(p)
    if (type(ids) is not tuple or not 1<=len(ids)<=c['block_count_max'] or len(ids)*p.width>c['entry_capacity'] or
            any(type(v) is not int or not 0<=v<=c['block_id_max'] for v in ids) or
            any(x>=y for x,y in zip(ids,ids[1:]))): raise ValueError('Blocks')
    if type(zs) is not tuple or len(zs)!=len(ids) or any(type(v) is not int or not 0<=v<=c['block_z_max'] for v in zs):
        raise ValueError('Weights')
    if (type(raw) is not tuple or len(raw)!=len(ids) or any(type(row) is not tuple or len(row)!=p.width or
            any(type(v) is not int or abs(v)>c['raw_max'] for v in row) for row in raw)): raise ValueError('Input')


def column_inputs(p,raw,w):
    c=constants(p); h=c['raw_max']; result=[]
    for sources,row in zip(raw,w['entries']):
        result.append([dict(sign_lhs=((source+h,e['magnitude']),(1,2*e['sign'])),
                            sign_rhs=((h,e['magnitude']),(1,1)),sign_gap=((e['sign_gap'],e['sign']),(1,1)),
                            bias=((e['magnitude'],c['bias']),(1,1)),quotient_product=((e['quotient'],),(c['divisor'],)),
                            division=((e['scaled_quotient'],e['remainder']),(1,1))) for source,e in zip(sources,row)])
    return result


def attach(p,ids,zs,raw,w):
    specs=column_specs(p)
    w['columns']=dict(probability_sum=bounded.witness(specs['shared_columns']['probability_sum'],zs,(1,)*len(zs)))
    for row,values in zip(w['entries'],column_inputs(p,raw,w)):
        for e,vs in zip(row,values): e['columns']={name:limbs.witness(s,*vs[name]) for name,s in specs['entry_columns'].items()}
    return w


def witness(p,ids,zs,raw):
    c=derive(p); inputs(p,ids,zs,raw); z=sum(zs); entries=[]
    if z>c['z_max']: raise ValueError('DivisorRange')
    for sources in raw:
        row=[]
        for source in sources:
            b=int(source<0); a=abs(source); q,remainder=divmod(a+c['bias'],c['divisor'])
            row.append(dict(sign=b,magnitude=a,sign_gap=a-b,quotient=q,scaled_quotient=q*c['divisor'],
                            remainder=remainder,output=(1-2*b)*q))
        entries.append(tuple(row))
    totals=tuple(sum(row[j]['output'] for row in entries) for j in range(p.width))
    return attach(p,ids,zs,raw,dict(block_ids=ids,weight_sum=z,entries=tuple(entries),totals=totals))


def check_relations(p,record,ids,zs,raw,w):
    """Conditional expected raw block sources; aggregate rounded totals fit directly in M31."""
    c=validate(p,record); inputs(p,ids,zs,raw); specs=column_specs(p)
    if (type(w) is not dict or set(w)!={'block_ids','weight_sum','entries','totals','columns'} or
            type(w['entries']) is not tuple or len(w['entries'])!=len(ids) or any(type(row) is not tuple or len(row)!=p.width for row in w['entries']) or
            type(w['totals']) is not tuple or len(w['totals'])!=p.width or any(type(t) is not int for t in w['totals']) or
            type(w['columns']) is not dict or w['columns'].keys()!=specs['shared_columns'].keys()): raise ValueError('Witness')
    if type(w['block_ids']) is not tuple or any(type(i) is not int for i in w['block_ids']) or w['block_ids']!=ids: raise ValueError('Blocks')
    if type(w['weight_sum']) is not int or not 0<=w['weight_sum']<=c['z_max'] or any(abs(t)>c['total_max'] for t in w['totals']):
        raise ValueError('Range')
    bounds=dict(sign=1,magnitude=c['raw_max'],sign_gap=c['raw_max'],quotient=c['rounded_max'],
                scaled_quotient=c['scaled_quotient_max'],remainder=c['remainder_max'])
    for row in w['entries']:
        for e in row:
            if (type(e) is not dict or set(e)!=set(bounds)|{'output','columns'} or any(type(e[k]) is not int for k in set(bounds)|{'output'}) or
                    type(e['columns']) is not dict or e['columns'].keys()!=specs['entry_columns'].keys()): raise ValueError('Witness')
            if any(not 0<=e[k]<=v for k,v in bounds.items()) or abs(e['output'])>c['rounded_max']: raise ValueError('Range')
    name='probability_sum'; col=w['columns'][name]
    bounded.check_relations(specs['shared_columns'][name],c['shared_columns'][name],zs,(1,)*len(zs),col)
    def digits(v): return limbs.digits(v,8,10)
    equal_digits(col['result'],digits(w['weight_sum']))
    for row,values in zip(w['entries'],column_inputs(p,raw,w)):
        for e,vs in zip(row,values):
            cols=e['columns']
            for name,s in specs['entry_columns'].items(): limbs.check_relations(s,c['entry_columns'][name],*vs[name],cols[name])
            equal_digits(cols['sign_lhs']['result'],cols['sign_rhs']['result'])
            equal_digits(cols['sign_gap']['result'],digits(e['magnitude']))
            equal_digits(cols['quotient_product']['result'],digits(e['scaled_quotient']))
            equal_digits(cols['bias']['result'],cols['division']['result'])
            if (e['output']-(1-2*e['sign'])*e['quotient'])%P: raise ValueError('OutputRelation')
    for j,t in enumerate(w['totals']):
        if (sum(row[j]['output'] for row in w['entries'])-t)%P: raise ValueError('SumRelation')
    return w['weight_sum'],w['totals']


def encode(p):
    c=derive(p); raw=TAG+unsigned(p.length,4)+unsigned(p.width,2)
    raw+=bytes([p.fraction,p.exponent,('dynamic','static').index(p.value_mode)])+unsigned(p.scale,2)+bytes([p.drop])
    raw+=unsigned(P,4)+bytes([8,len(SCALARS)])+b''.join(unsigned(c[k],20) for k in SCALARS)
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
