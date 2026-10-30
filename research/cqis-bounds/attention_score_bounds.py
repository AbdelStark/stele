"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: scaled QK scores, no proof consumer."""
from dataclasses import asdict, dataclass
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/attention-score-bounds/v1\0'
SCALARS=('q_code_max','k_code_max','q_scale_min','q_scale_max','k_scale_min','k_scale_max','dot_max','sign_side_max',
         'query_scaled_max','key_scaled_max','product_max','left_factor','divisor','bias','numerator_max','biased_max',
         'score_max','scaled_quotient_max','remainder_max','output_offset_max')


@dataclass(frozen=True)
class Spec:
    width: int
    fq: int
    fk: int
    f: int
    q_mode: str
    q_scale: int
    k_mode: str
    k_scale: int
    score_m: int
    score_e: int


def constants(p):
    if (type(p) is not Spec or any(type(getattr(p,k)) is not int for k in
            ('width','fq','fk','f','q_scale','k_scale','score_m','score_e')) or not 1<=p.width<=16384 or
            any(not 0<=v<=30 for v in (p.fq,p.fk,p.f)) or not 1<=p.score_m<=65535 or not -62<=p.score_e<=30):
        raise ValueError('Spec')
    def policy(mode,s):
        if type(mode) is not str or mode not in ('dynamic','static') or (s!=0 if mode=='dynamic' else not 1<=s<=65535):
            raise ValueError('Spec')
        return (127,0,259) if mode=='dynamic' else (min(127,(65536+s)//(2*s)),s,s)
    cq,ql,qh=policy(p.q_mode,p.q_scale); ck,kl,kh=policy(p.k_mode,p.k_scale)
    dot=p.width*cq*ck; query=dot*qh; key=query*kh; product=key*p.score_m
    e=p.score_e-p.fq-p.fk+p.f; a=1<<max(e,0); d=1<<max(-e,0); bias=d//2; n=product*a; score=(n+bias)//d
    # Same static contract as projected_attention.Params, including zero actual inputs.
    if score>=1<<31: raise ValueError('ScoreBound')
    return dict(asdict(p),prime=P,q_code_max=cq,k_code_max=ck,q_scale_min=ql,q_scale_max=qh,k_scale_min=kl,k_scale_max=kh,
                dot_max=dot,sign_side_max=dot+1,query_scaled_max=query,key_scaled_max=key,product_max=product,
                left_factor=a,divisor=d,bias=bias,numerator_max=n,biased_max=n+bias,score_max=score,
                scaled_quotient_max=score*d,remainder_max=d-1,output_offset_max=2*score)


def column_specs(p):
    c=constants(p); n=c['numerator_max']; d=c['divisor']; score=c['score_max']
    return dict(query_scale=limbs.Spec(1,c['dot_max'],c['q_scale_max'],8),
                key_scale=limbs.Spec(1,c['query_scaled_max'],c['k_scale_max'],8),
                score_multiplier=limbs.Spec(1,c['key_scaled_max'],p.score_m,8),left=limbs.Spec(1,c['product_max'],c['left_factor'],8),
                bias=limbs.Spec(2,max(n,c['bias']),1,8),quotient_product=limbs.Spec(1,score,d,8),
                division=limbs.Spec(2,max(score*d,d-1),1,8),output_lhs=limbs.Spec(2,2*score,2,8),
                output_rhs=limbs.Spec(2,score,1,8))


def derive(p):
    c=constants(p)
    if 2*c['sign_side_max']>=P: raise ValueError('FieldBound')
    return dict(c,columns={name:limbs.derive(s) for name,s in column_specs(p).items()})


def validate(p,record):
    c=derive(p)
    if not same(record,c): raise ValueError('Certificate')
    return c


def inputs(p,q,k,qs,ks):
    c=constants(p)
    for row,scale,prefix in ((q,qs,'q'),(k,ks,'k')):
        if (type(row) is not tuple or len(row)!=p.width or any(type(v) is not int or abs(v)>c[prefix+'_code_max'] for v in row) or
                type(scale) is not int or not c[prefix+'_scale_min']<=scale<=c[prefix+'_scale_max'] or
                (scale==0 and any(row))): raise ValueError('Input')


def column_inputs(p,qs,ks,w):
    c=constants(p); score=c['score_max']
    return dict(query_scale=((w['magnitude'],),(qs,)),key_scale=((w['query_scaled'],),(ks,)),
                score_multiplier=((w['key_scaled'],),(p.score_m,)),left=((w['product'],),(c['left_factor'],)),
                bias=((w['numerator'],c['bias']),(1,1)),quotient_product=((w['quotient'],),(c['divisor'],)),
                division=((w['scaled_quotient'],w['remainder']),(1,1)),
                output_lhs=((w['output']+score,w['quotient']),(1,2*w['sign'])),output_rhs=((score,w['quotient']),(1,1)))


def attach(p,qs,ks,w):
    values=column_inputs(p,qs,ks,w)
    w['columns']={name:limbs.witness(s,*values[name]) for name,s in column_specs(p).items()}
    return w


def witness(p,q,k,qs,ks):
    c=derive(p); inputs(p,q,k,qs,ks); dot=sum(x*y for x,y in zip(q,k)); b=int(dot<0); a=abs(dot)
    query=a*qs; key=query*ks; product=key*p.score_m; n=product*c['left_factor']; quotient,remainder=divmod(n+c['bias'],c['divisor'])
    return attach(p,qs,ks,dict(dot=dot,sign=b,magnitude=a,sign_gap=a-b,query_scaled=query,key_scaled=key,product=product,
                              numerator=n,quotient=quotient,scaled_quotient=quotient*c['divisor'],remainder=remainder,output=(1-2*b)*quotient))


def check_relations(p,record,q,k,qs,ks,w):
    """Conditional Q/K source arrays. Wide products and signed outputs never compare modulo p."""
    c=validate(p,record); inputs(p,q,k,qs,ks)
    bounds=dict(sign=1,magnitude=c['dot_max'],sign_gap=c['dot_max'],query_scaled=c['query_scaled_max'],
                key_scaled=c['key_scaled_max'],product=c['product_max'],numerator=c['numerator_max'],
                quotient=c['score_max'],scaled_quotient=c['scaled_quotient_max'],remainder=c['remainder_max'])
    if (type(w) is not dict or set(w)!=set(bounds)|{'dot','output','columns'} or
            any(type(w[k]) is not int for k in set(bounds)|{'dot','output'}) or type(w['columns']) is not dict or
            w['columns'].keys()!=c['columns'].keys()): raise ValueError('Witness')
    if any(not 0<=w[k]<=v for k,v in bounds.items()) or abs(w['dot'])>c['dot_max'] or abs(w['output'])>c['score_max']:
        raise ValueError('Range')
    if (sum(x*y for x,y in zip(q,k))-w['dot'])%P: raise ValueError('DotRelation')
    if (w['dot']-(1-2*w['sign'])*w['magnitude'])%P or (w['sign_gap']+w['sign']-w['magnitude'])%P:
        raise ValueError('SignRelation')
    values=column_inputs(p,qs,ks,w); cols=w['columns']
    for name,s in column_specs(p).items(): limbs.check_relations(s,c['columns'][name],*values[name],cols[name])
    for role,field in (('query_scale','query_scaled'),('key_scale','key_scaled'),('score_multiplier','product'),
                       ('left','numerator'),('quotient_product','scaled_quotient')):
        equal_digits(cols[role]['result'],limbs.digits(w[field],8,20))
    equal_digits(cols['bias']['result'],cols['division']['result'])
    equal_digits(cols['output_lhs']['result'],cols['output_rhs']['result'])
    return w['output']


def encode(p):
    c=derive(p); raw=TAG+unsigned(p.width,2)+bytes([p.fq,p.fk,p.f,('dynamic','static').index(p.q_mode)])+unsigned(p.q_scale,2)
    raw+=bytes([('dynamic','static').index(p.k_mode)])+unsigned(p.k_scale,2)+unsigned(p.score_m,2)+p.score_e.to_bytes(1,'little',signed=True)
    raw+=unsigned(P,4)+bytes([8,len(SCALARS)])+b''.join(unsigned(c[k],20) for k in SCALARS)+bytes([len(c['columns'])])
    for i,rec in enumerate(c['columns'].values(),1):
        raw+=bytes([i])+unsigned(rec['count'],4)+b''.join(unsigned(rec[k],20) for k in ('left_max','right_max','result_max'))
        raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
        raw+=b''.join(unsigned(v,4) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    if len(raw)>4096: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>4096 or raw!=expected: raise ValueError('Encoding')
