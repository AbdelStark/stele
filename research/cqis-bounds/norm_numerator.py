"""Q26/Q31 RMSNorm numerator: RFC-0021 §2.3 / RFC-0022 §2.3, Draft A3.

O(B) exact source views plus complete range/product consumers; revealing research.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import limb_product as lp
import function_identity as fn

need=r.need
PREFIX=b'stele/research/q26/norm-numerator/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=norm.constants(p.schema); base=(1<<63)+(1<<18)*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    statistic=r.Spec(4096*p.identity+1,base+1,(cert['S_max'],),p.repetitions); _,b,_,width,_,_=r.derive(statistic,d)
    product=lp.Spec(norm.column_specs(p.schema)['numerator'],64*p.identity+1,base+2,p.output,p.repetitions); layout=lp.derive(product,d)
    need(width<=8 and layout['layout']['planes']>=width,'Capacity')
    s=p.schema; function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQ',1,d,p.repetitions,p.identity,p.source,p.output)+fn.encode(function)
    return dict(statistic=statistic,product=product,layout=layout,cert=cert,b=b,width=width,base=base,raw=raw)


def full_source(v,words):
    r.vector(words,v['width'])
    return words+[0]*(8-v['width'])


def source(v,words):
    r.vector(words,v['width']); c=v['cert']
    return [value for j in range(v['layout']['layout']['planes']) for value in
            (words[j] if j<v['width'] else 0,c['unit']>>(8*j)&255,c['ed']>>(8*j)&255,c['en']>>(8*j)&255)]


def witness(p,statistic):
    v=derive(p,4); need(type(statistic) is int and 0<=statistic<=v['cert']['S_max'],'Statistic')
    return lp.limbs.witness(v['product'].schema,(statistic,v['cert']['unit']),(p.schema.ed,p.schema.en))


def expected_roots(p,statistic,numerator):
    v=derive(p,4); need(type(statistic) is int and 0<=statistic<=v['cert']['S_max'],'Statistic')
    need(type(numerator) is int and 0<=numerator<=v['cert']['N_max'],'Numerator')
    return [r.root(p.source,lp.limbs.digits(statistic,8,8)),r.root(p.output,lp.limbs.digits(numerator,8,v['layout']['s']))]


def transcript(v,roots,states,d):
    need(type(roots) is list and len(roots)==4 and type(states) is list and len(states)==2 and
         all(type(x) is bytes and len(x)==32 for x in roots+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots+states),d)


def prepare(p,statistic,d):
    v=derive(p,d); w=witness(p,statistic)
    return dict(statistic=r.prove(v['statistic'],[statistic],d),product=lp.prove(v['product'],w,d))


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; only verify authorizes acceptance."""
    v=derive(p,d); proof={name:pairs[name][0] for name in ('statistic','product')}; words=proof['statistic']['words']
    roots=[r.root(p.source,full_source(v,words)),lp.cr.source_root(v['layout']['output'],proof['product']['output']['words']),
           r.source_root(v['statistic'],words),lp.ls.source_root(v['layout']['input'],source(v,words))]
    return proof,transcript(v,roots,[pairs[name][1] for name in ('statistic','product')],d).state


def prove(p,statistic,d):
    return assemble(p,prepare(p,statistic,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'statistic','product'},'ProofShape')
    try:
        part=proof['statistic']; need(type(part) is dict and 'words' in part,'ProofShape'); words=part['words']
        need(r.root(p.source,full_source(v,words))==expected[0],'CommitmentMismatch')
        bounded_root=r.source_root(v['statistic'],words); statistic=r.verify(v['statistic'],bounded_root,part,d)
    except ValueError as error: raise ValueError('Statistic:'+str(error)) from None
    actual=source(v,words)
    try:
        part=proof['product']; need(type(part) is dict and type(part.get('input')) is dict and 'digits' in part['input'],'ProofShape')
        lp.ls.source_root(v['layout']['input'],part['input']['digits']); need(part['input']['digits']==actual,'SourceJoin')
        source_root=lp.ls.source_root(v['layout']['input'],actual); product=lp.verify(v['product'],[source_root,expected[1]],part,d)
    except ValueError as error: raise ValueError('Product:'+str(error)) from None
    t=transcript(v,expected+[bounded_root,source_root],[statistic['state'],product['state']],d); a,b=statistic['account'],product['account']
    return dict(state=t.state,statistic=statistic,product=product,draws=dict(t.draws),
        account=dict(identities=[(a['identity_numerator'],a['identity_power'])]+b['identities'],lookup_reduction_numerator=a['lookup_reduction_numerator']+b['lookup_reduction_numerator'],
            range_reduction_numerator=a['range_reduction_numerator']+b['range_reduction_numerator'],
            product_identity_numerator=b['product_identity_numerator'],product_reduction_numerator=b['product_reduction_numerator'],denominator=r.sc.P**d))
