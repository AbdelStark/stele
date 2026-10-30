"""Q26/Q31 RMSNorm statistic: RFC-0021 §2.3 / RFC-0022 §2.3, Draft A3.

O(N) duplicated byte views plus complete signed/range/product consumers.
Revealing research; no private PCS or full normalization admission.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import signed_source as ss
import limb_product as lp
import function_identity as fn

r=ss.r
need=r.need
PREFIX=b'stele/research/q26/norm-statistic/v1\0'


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
    cert=norm.constants(p.schema); need(p.schema.d<=2048,'Capacity')
    base=(1<<63)+(1<<18)*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    signed=ss.Spec(512*p.identity+1,p.source,base+1,16,p.schema.d,p.repetitions); ss.derive(signed,d)
    product=lp.Spec(norm.column_specs(p.schema)['statistic'],64*p.identity+1,base+2,p.output,p.repetitions); layout=lp.derive(product,d)
    need(layout['s']==8 and layout['layout']['planes']==2,'Capacity')
    s=p.schema; function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQ',1,d,p.repetitions,p.identity,p.source,p.output)+fn.encode(function)
    return dict(signed=signed,product=product,layout=layout,cert=cert,a=layout['layout']['a'],n=layout['layout']['n'],base=base,raw=raw)


def duplicate(magnitude,n):
    r.vector(magnitude,2*n)
    return magnitude[:n]*2+magnitude[n:]*2


def witness(p,xs):
    v=derive(p,4); magnitude=tuple(ss.witness(v['signed'],xs)[1])
    return lp.limbs.witness(v['product'].schema,magnitude,magnitude)


def expected_roots(p,xs,statistic):
    v=derive(p,4); raw=ss.witness(v['signed'],xs)[0]; child=ss.derive(v['signed'],4)['ranges'][0]
    need(type(statistic) is int and 0<=statistic<=v['cert']['S_max'],'Statistic')
    return [r.source_root(child,r.witness(child,raw)[0]),r.root(p.output,lp.limbs.digits(statistic,8,8))]


def transcript(v,roots,states,d):
    need(type(roots) is list and len(roots)==4 and type(states) is list and len(states)==2 and
         all(type(x) is bytes and len(x)==32 for x in roots+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots+states),d)


def prepare(p,xs,d):
    v=derive(p,d); w=witness(p,xs)
    return dict(source=ss.prove(v['signed'],xs,d),product=lp.prove(v['product'],w,d))


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; only verify authorizes acceptance."""
    v=derive(p,d); proof={name:pairs[name][0] for name in ('source','product')}
    source=proof['source']; magnitude=source['ranges'][1]['words']; proof['magnitude_root']=r.root(v['base']+1,magnitude)
    roots=[r.source_root(ss.derive(v['signed'],d)['ranges'][0],source['ranges'][0]['words']),
           lp.cr.source_root(v['layout']['output'],proof['product']['output']['words']),proof['magnitude_root'],
           lp.ls.source_root(v['layout']['input'],duplicate(magnitude,v['n']))]
    return proof,transcript(v,roots,[pairs[name][1] for name in ('source','product')],d).state


def prove(p,xs,d):
    return assemble(p,prepare(p,xs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'source','product','magnitude_root'},'ProofShape')
    need(type(proof['magnitude_root']) is bytes and len(proof['magnitude_root'])==32,'Root')
    try: signed=ss.verify(v['signed'],[expected[0],proof['magnitude_root']],proof['source'],d)
    except ValueError as error: raise ValueError('Source:'+str(error)) from None
    actual=duplicate(proof['source']['ranges'][1]['words'],v['n'])
    try:
        part=proof['product']; need(type(part) is dict and type(part.get('input')) is dict and 'digits' in part['input'],'ProofShape')
        lp.ls.source_root(v['layout']['input'],part['input']['digits']); need(part['input']['digits']==actual,'SourceJoin')
        source_root=lp.ls.source_root(v['layout']['input'],actual)
        product=lp.verify(v['product'],[source_root,expected[1]],part,d)
    except ValueError as error: raise ValueError('Product:'+str(error)) from None
    t=transcript(v,expected+[proof['magnitude_root'],source_root],[signed['state'],product['state']],d)
    a,b=signed['account'],product['account']
    return dict(state=t.state,signed=signed,product=product,draws=dict(t.draws),
        account=dict(identities=a['identities']+b['identities'],lookup_reduction_numerator=a['lookup_reduction_numerator']+b['lookup_reduction_numerator'],
            range_reduction_numerator=a['range_reduction_numerator']+b['range_reduction_numerator'],
            product_identity_numerator=b['product_identity_numerator'],product_reduction_numerator=b['product_reduction_numerator'],denominator=r.sc.P**d))
