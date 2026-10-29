"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: signed variable division, no proof consumer."""
from dataclasses import asdict, dataclass
import attention_sum_bounds as sums
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/attention-normalization-bounds/v1\0'
SCALARS=('probability_max','restored_max','block_raw_max','rounded_block_max','block_count_max','total_max',
         'z_min','z_max','left_factor','right_factor','numerator_max','denominator_max','double_denominator_max',
         'biased_max','quotient_max','scaled_quotient_max','remainder_max','output_max','source_offset_max','source_gap_max')


@dataclass(frozen=True)
class Spec:
    length: int
    width: int
    fraction: int
    output_fraction: int
    exponent: int
    value_mode: str
    scale: int
    accumulation: str
    drop: int


def constants(p):
    if (type(p) is not Spec or type(p.output_fraction) is not int or not 0<=p.output_fraction<=30 or
            type(p.drop) is not int or not 0<=p.drop<=62 or (p.accumulation=='exact' and p.drop!=0)): raise ValueError('Spec')
    c=sums.constants(sums.Spec(p.length,p.width,p.fraction,p.exponent,p.value_mode,p.scale,p.accumulation))
    probability=c['probability_max']; s=c['restored_max']; raw=1024*probability*s; divisor=1<<p.drop
    small=0 if p.accumulation=='exact' else (raw+divisor//2)//divisor
    if small>32767: raise ValueError('BlockBound')
    blocks=0 if p.accumulation=='exact' else (p.length+1023)//1024
    total=p.length*probability*s if p.accumulation=='exact' else blocks*small
    z=p.length*probability; exponent=p.output_fraction-p.fraction+p.drop
    a=1<<max(exponent,0); b=1<<max(-exponent,0); u=total*a; d=z*b
    return dict(asdict(p),prime=P,probability_max=probability,restored_max=s,block_raw_max=raw,
                rounded_block_max=small,block_count_max=blocks,total_max=total,z_min=probability,z_max=z,
                left_factor=a,right_factor=b,numerator_max=u,denominator_max=d,double_denominator_max=2*d,
                biased_max=2*u+d,quotient_max=32768,scaled_quotient_max=32768*d,remainder_max=2*d-1,
                output_max=32768,source_offset_max=2*total,source_gap_max=total)


def column_specs(p):
    c=constants(p); t=c['total_max']; u=c['numerator_max']; d=c['denominator_max']
    return dict(shared_columns=dict(denominator=limbs.Spec(1,c['z_max'],c['right_factor'],8),
                                    doubled_denominator=limbs.Spec(1,d,2,8)),
                entry_columns=dict(sign_lhs=limbs.Spec(2,2*t,2,8),sign_rhs=limbs.Spec(2,t,1,8),
                                   sign_gap=limbs.Spec(2,max(t,1),1,8),numerator=limbs.Spec(1,t,c['left_factor'],8),
                                   biased=limbs.Spec(2,max(u,d),2,8),quotient_product=limbs.Spec(1,32768,d,8),
                                   division=limbs.Spec(2,max(32768*d,2*d-1),2,8),remainder_gap=limbs.Spec(3,2*d-1,1,8)))


def derive(p):
    c=constants(p)
    if 2*c['output_max']>=P: raise ValueError('FieldBound')
    return dict(c,**{group:{name:limbs.derive(s) for name,s in specs.items()} for group,specs in column_specs(p).items()})


def validate(p,record):
    c=derive(p)
    if not same(record,c): raise ValueError('Certificate')
    return c


def inputs(p,z,totals):
    c=constants(p)
    if type(z) is not int or not c['z_min']<=z<=c['z_max']: raise ValueError('Divisor')
    if type(totals) is not tuple or len(totals)!=p.width or any(type(t) is not int or abs(t)>c['total_max'] for t in totals):
        raise ValueError('Input')


def column_inputs(p,z,totals,w):
    c=constants(p); t=c['total_max']; d=w['denominator']
    shared=dict(denominator=((z,),(c['right_factor'],)),doubled_denominator=((d,),(2,)))
    entries=[]
    for source,e in zip(totals,w['entries']):
        entries.append(dict(sign_lhs=((source+t,e['magnitude']),(1,2*e['sign'])),
                            sign_rhs=((t,e['magnitude']),(1,1)),sign_gap=((e['sign_gap'],e['sign']),(1,1)),
                            numerator=((e['magnitude'],),(c['left_factor'],)),biased=((e['numerator'],d),(2,1)),
                            quotient_product=((e['quotient'],),(d,)),division=((e['scaled_quotient'],e['remainder']),(2,1)),
                            remainder_gap=((e['remainder'],e['remainder_gap'],1),(1,1,1))))
    return shared,entries


def attach(p,z,totals,w):
    specs=column_specs(p); shared,entries=column_inputs(p,z,totals,w)
    w['columns']={name:limbs.witness(s,*shared[name]) for name,s in specs['shared_columns'].items()}
    for e,values in zip(w['entries'],entries):
        e['columns']={name:limbs.witness(s,*values[name]) for name,s in specs['entry_columns'].items()}
    return w


def witness(p,z,totals):
    c=derive(p); inputs(p,z,totals); d=z*c['right_factor']; entries=[]
    for t in totals:
        b=int(t<0); a=abs(t); u=a*c['left_factor']; q,remainder=divmod(2*u+d,2*d); output=(1-2*b)*q
        if not -32768<=output<=32767: raise ValueError('OutputRange')
        entries.append(dict(sign=b,magnitude=a,sign_gap=a-b,numerator=u,quotient=q,scaled_quotient=q*d,
                            remainder=remainder,remainder_gap=2*d-1-remainder,output=output))
    return attach(p,z,totals,dict(denominator=d,entries=tuple(entries)))


def check_relations(p,record,z,totals,w):
    """Conditional expected sum/divisor sources; strict remainder bound is a digit relation."""
    c=validate(p,record); inputs(p,z,totals); specs=column_specs(p)
    if (type(w) is not dict or set(w)!={'denominator','entries','columns'} or type(w['entries']) is not tuple or
            len(w['entries'])!=p.width or type(w['columns']) is not dict or w['columns'].keys()!=specs['shared_columns'].keys()):
        raise ValueError('Witness')
    if type(w['denominator']) is not int or not 1<=w['denominator']<=c['denominator_max']: raise ValueError('Range')
    bounds=dict(sign=1,magnitude=c['total_max'],sign_gap=c['total_max'],numerator=c['numerator_max'],
                quotient=32768,scaled_quotient=c['scaled_quotient_max'],remainder=c['remainder_max'],remainder_gap=c['remainder_max'])
    for e in w['entries']:
        if (type(e) is not dict or set(e)!=set(bounds)|{'output','columns'} or any(type(e[k]) is not int for k in set(bounds)|{'output'}) or
                type(e['columns']) is not dict or e['columns'].keys()!=specs['entry_columns'].keys()): raise ValueError('Witness')
        if any(not 0<=e[k]<=v for k,v in bounds.items()) or not -32768<=e['output']<=32767: raise ValueError('Range')
    shared,entries=column_inputs(p,z,totals,w)
    def digits(v): return limbs.digits(v,8,20)
    for name,s in specs['shared_columns'].items(): limbs.check_relations(s,c['shared_columns'][name],*shared[name],w['columns'][name])
    equal_digits(w['columns']['denominator']['result'],digits(w['denominator']))
    for e,values in zip(w['entries'],entries):
        cols=e['columns']
        for name,s in specs['entry_columns'].items(): limbs.check_relations(s,c['entry_columns'][name],*values[name],cols[name])
        equal_digits(cols['sign_lhs']['result'],cols['sign_rhs']['result'])
        equal_digits(cols['sign_gap']['result'],digits(e['magnitude']))
        equal_digits(cols['numerator']['result'],digits(e['numerator']))
        equal_digits(cols['quotient_product']['result'],digits(e['scaled_quotient']))
        equal_digits(cols['biased']['result'],cols['division']['result'])
        equal_digits(cols['remainder_gap']['result'],w['columns']['doubled_denominator']['result'])
        if (e['output']-(1-2*e['sign'])*e['quotient'])%P: raise ValueError('OutputRelation')
    return tuple(e['output'] for e in w['entries'])


def encode(p):
    c=derive(p); raw=TAG+unsigned(p.length,4)+unsigned(p.width,2)
    raw+=bytes([p.fraction,p.output_fraction,p.exponent,('dynamic','static').index(p.value_mode)])+unsigned(p.scale,2)
    raw+=bytes([('exact','block1024').index(p.accumulation),p.drop])+unsigned(P,4)+bytes([8,len(SCALARS)])
    raw+=b''.join(unsigned(c[k],20) for k in SCALARS)
    for group in ('shared_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,rec in enumerate(c[group].values(),1):
            raw+=bytes([i])+unsigned(rec['count'],4)+b''.join(unsigned(rec[k],20) for k in ('left_max','right_max','result_max'))
            raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(unsigned(v,4) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    if len(raw)>4096: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>4096 or raw!=expected: raise ValueError('Encoding')
