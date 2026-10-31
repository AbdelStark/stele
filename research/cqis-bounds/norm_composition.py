"""RFC-0022 §2.3 complete arithmetic / revealing Draft RFC-0004 A3.

O(N) source joins plus seven complete consumers; no new parent challenge.
Native/model/private inference and physical source ownership remain separate.
"""
from dataclasses import dataclass
import struct
import norm_configured_output as configured
import norm_statistic_full as statistic
import norm_numerator as numerator
import norm_mantissa_product as mantissa
import norm_sum as summation
import norm_remainder as remainder
import norm_rsqrt as rsqrt
import certified_rmsnorm as canonical

norm=configured.norm
r=configured.r
need=r.need
NAMES=configured.NAMES+('statistic','mantissa','normalized_product','normalized_remainder')
MODULES=(('configured',configured,'Configured'),('statistic',statistic,'Statistic'),('numerator',numerator,'Numerator'),('mantissa_product',mantissa,'MantissaProduct'),('normal_sum',summation,'NormalSum'),('normal_remainder',remainder,'NormalRemainder'),('reciprocal',rsqrt,'Reciprocal'))
ROUTES=(tuple(range(15)),(5,15),(15,0),(16,3,17),(17,18,2),(3,18),(16,11))
PREFIX=b'stele/research/q26/norm-composition/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    exponent: int
    scaled: int
    divisor: int
    factors: int
    left: int
    right: int
    xy: int
    sign: int
    output: int
    magnitude: int
    reciprocal: int
    product: int
    quotient_product: int
    remainder: int
    statistic: int
    mantissa: int
    normalized_product: int
    normalized_remainder: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<24 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<38)*p.identity;ids=tuple(getattr(p,name) for name in NAMES)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<38) for x in ids) and len(set(ids))==19,'Spec')
    children=dict(configured=configured.Spec(p.schema,16*p.identity+1,*ids[:15],p.repetitions),
        statistic=statistic.Spec(p.schema,(1<<20)*p.identity+1,p.left,p.statistic,p.repetitions),
        numerator=numerator.Spec(p.schema,(1<<20)*p.identity+2,p.statistic,p.source,p.repetitions),
        mantissa_product=mantissa.Spec(p.schema,(1<<20)*p.identity+3,p.mantissa,p.divisor,p.normalized_product,p.repetitions),
        normal_sum=summation.Spec(p.schema,(1<<20)*p.identity+4,p.normalized_product,p.normalized_remainder,p.scaled,p.repetitions),
        normal_remainder=remainder.Spec(p.schema,(1<<26)*p.identity+1,p.divisor,p.normalized_remainder,p.repetitions),
        reciprocal=rsqrt.Spec(p.schema,(1<<26)*p.identity+2,p.mantissa,p.reciprocal,p.repetitions))
    for name,module,_ in MODULES:
        # Metadata validation does not generate the large reciprocal table.
        (rsqrt.metadata if name=='reciprocal' else module.derive)(children[name],d)
    s=p.schema;function=configured.fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBB'+'Q'*(1+len(NAMES)),1,d,p.repetitions,p.identity,*ids)+configured.fn.encode(function)
    return dict(**children,base=base,raw=raw)


def witness(p,xs,hs):
    """Producer only; canonical integer evaluation never authorizes verify."""
    derive(p,4);need(type(xs) is list and type(hs) is list,'Input');norm.inputs(p.schema,tuple(xs),tuple(hs));s=p.schema
    result=canonical.evaluate(canonical.Parameters(s.d,s.F,s.G,s.E,s.en,s.ed),xs,hs);w=dict(result['norm']);A,D=canonical.scaled_ratio(w['N'],w['P'],w['a'])
    return dict(w,A=A,D=D,MD=w['M']*D,output=result['output'])


def expected_roots(p,xs,hs):
    v=derive(p,4);w=witness(p,xs,hs);bound=configured.expected_roots(v['configured'],w['N'],w['a'],xs,hs,w['J']);mp=mantissa.expected_roots(v['mantissa_product'],w['M'],w['D'],w['MD'])
    return bound+[statistic.expected_roots(v['statistic'],xs,w['S'])[1],mp[0],mp[2],remainder.expected_roots(v['normal_remainder'],w['D'],w['R'])[1]]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==19 and type(states) is list and len(states)==7 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,hs,d):
    v=derive(p,d);w=witness(p,xs,hs)
    return dict(configured=configured.prove(v['configured'],w['N'],w['a'],xs,hs,w['J'],d),
        statistic=statistic.prove(v['statistic'],xs,d),numerator=numerator.prove(v['numerator'],w['S'],d),
        mantissa_product=mantissa.prove(v['mantissa_product'],w['M'],w['D'],d),normal_sum=summation.prove(v['normal_sum'],w['MD'],w['R'],d),
        normal_remainder=remainder.prove(v['normal_remainder'],w['D'],w['R'],d),reciprocal=rsqrt.prove(v['reciprocal'],w['M'],d))


def assemble(p,pairs,bound,d):
    """Producer only; supplied states/roots confer no acceptance authority."""
    v=derive(p,d);proof={name:pairs[name][0] for name,_,_ in MODULES};states=[pairs[name][1] for name,_,_ in MODULES]
    return proof,transcript(v,bound,states,d).state


def prove(p,xs,hs,d):
    return assemble(p,prepare(p,xs,hs,d),expected_roots(p,xs,hs),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==19 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={name for name,_,_ in MODULES},'ProofShape');children=[]
    for (name,module,label),indices in zip(MODULES,ROUTES):
        try:children.append(module.verify(v[name],[expected[i] for i in indices],proof[name],d))
        except ValueError as error:raise ValueError(label+':'+str(error)) from None
    t=transcript(v,expected,[child['state'] for child in children],d);accounts=[child['account'] for child in children[:6]];lookup=children[6]['account'];products=[accounts[i] for i in (0,2,3,4)]
    # Keep the four independent polynomial identities; none is repeated or
    # squared with lookup repetitions. Full receipts retain every child event.
    account=dict(identities=sum((item['identities'] for item in accounts),[])+[(lookup['identity_numerator'],lookup['identity_power'])],
        lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in accounts)+lookup['reduction_numerator'],
        range_reduction_numerator=sum(item['range_reduction_numerator'] for item in accounts),statistic_reduction_numerator=accounts[1]['statistic_reduction_numerator'],
        selection_reduction_numerator=accounts[0]['selection_reduction_numerator'],product_identities=[item['product_identity_numerator'] for item in products],
        product_reduction_numerator=sum(item['product_reduction_numerator'] for item in products),denominator=r.sc.P**d)
    return dict(state=t.state,children=children,draws=dict(t.draws),account=account)
