"""Q26/Q31 scaled RMSNorm numerator: RFC-0022 §2.3, Draft RFC-0004 A3.

O(B) source views and all exponent/limb-product consumers; revealing research.
"""
from dataclasses import dataclass
import struct
import norm_exponent as ex
import limb_product as lp

norm=ex.norm
r=ex.r
need=r.need
PREFIX=b'stele/research/q26/norm-scaled/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    exponent: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=norm.constants(p.schema); base=(1<<63)+(1<<18)*p.identity; ids=(p.source,p.exponent,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in ids) and len(set(ids))==3,'Spec')
    exponent=ex.Spec(p.schema,64*p.identity+1,p.exponent,base+1,p.repetitions); ex.derive(exponent,d)
    roles=norm.column_specs(p.schema); nslots=1<<len(lp.limbs.derive(roles['numerator'])['result_caps']).bit_length()
    product=lp.Spec(roles['scaled'],64*p.identity+2,base+2,p.output,p.repetitions); layout=lp.derive(product,d)
    s=p.schema; function=ex.fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQ',1,d,p.repetitions,p.identity,*ids)+ex.fn.encode(function)
    return dict(exponent=exponent,product=product,layout=layout,nslots=nslots,cert=cert,base=base,raw=raw)


def numerator_source(v,digits):
    r.vector(digits,v['layout']['layout']['cells']); left=digits[::2]; n=v['nslots']
    need(not any(left[n:]),'SourcePadding')
    return left[:n]+[0]*max(0,n-len(left))


def source(v,digits,factors):
    r.vector(digits,v['layout']['layout']['cells']); r.vector(factors,16)
    return [x for j,left in enumerate(digits[::2]) for x in (left,factors[j] if j<8 else 0)]


def witness(p,n,a):
    v=derive(p,4); need(type(n) is int and 0<=n<=v['cert']['N_max'],'Numerator'); ex.witness(v['exponent'],a)
    return lp.limbs.witness(v['product'].schema,(n,),(4**max(-a,0),))


def expected_roots(p,n,a,scaled):
    v=derive(p,4); witness(p,n,a)
    need(type(scaled) is int and 0<=scaled<=v['cert']['A_max'],'Scaled')
    return [r.root(p.source,lp.limbs.digits(n,8,v['nslots'])),ex.expected_roots(v['exponent'],a)[0],
            r.root(p.output,lp.limbs.digits(scaled,8,v['layout']['s']))]


def transcript(v,roots,states,d):
    need(type(roots) is list and len(roots)==5 and type(states) is list and len(states)==2 and
         all(type(x) is bytes and len(x)==32 for x in roots+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots+states),d)


def prepare(p,n,a,d):
    v=derive(p,d); w=witness(p,n,a)
    return dict(exponent=ex.prove(v['exponent'],a,d),product=lp.prove(v['product'],w,d))


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; verify is the only acceptance path."""
    v=derive(p,d); proof={name:pairs[name][0] for name in ('exponent','product')}; src=proof['product']['input']['digits']
    er=ex.roots(v['exponent'],proof['exponent']['offset'],proof['exponent']['factors'])
    roots=[r.root(p.source,numerator_source(v,src)),er[0],lp.cr.source_root(v['layout']['output'],proof['product']['output']['words']),
           er[1],lp.ls.source_root(v['layout']['input'],src)]
    return proof,transcript(v,roots,[pairs[name][1] for name in ('exponent','product')],d).state


def prove(p,n,a,d):
    return assemble(p,prepare(p,n,a,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'exponent','product'},'ProofShape')
    try:
        part=proof['exponent']; need(type(part) is dict and 'factors' in part,'ProofShape'); factors=part['factors']; r.vector(factors,16)
        factor_root=r.root(v['base']+1,factors); exponent=ex.verify(v['exponent'],[expected[1],factor_root],part,d)
    except ValueError as error: raise ValueError('Exponent:'+str(error)) from None
    try:
        part=proof['product']; need(type(part) is dict and type(part.get('input')) is dict and 'digits' in part['input'],'ProofShape')
        digits=part['input']['digits']; numerator=numerator_source(v,digits)
    except ValueError as error: raise ValueError('Product:'+str(error)) from None
    need(r.root(p.source,numerator)==expected[0],'Numerator:CommitmentMismatch')
    try:
        need(digits==source(v,digits,factors),'SourceJoin'); source_root=lp.ls.source_root(v['layout']['input'],digits)
        product=lp.verify(v['product'],[source_root,expected[2]],part,d)
    except ValueError as error: raise ValueError('Product:'+str(error)) from None
    t=transcript(v,expected+[factor_root,source_root],[exponent['state'],product['state']],d); a,b=exponent['account'],product['account']
    return dict(state=t.state,exponent=exponent,product=product,draws=dict(t.draws),
        account=dict(identities=a['identities']+b['identities'],lookup_reduction_numerator=a['lookup_reduction_numerator']+b['lookup_reduction_numerator'],
            range_reduction_numerator=a['range_reduction_numerator']+b['range_reduction_numerator'],selection_reduction_numerator=a['selection_reduction_numerator'],
            product_identity_numerator=b['product_identity_numerator'],product_reduction_numerator=b['product_reduction_numerator'],denominator=r.sc.P**d))
