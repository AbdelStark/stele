"""Q26/Q31 same-a output factors: RFC-0021 §2.3 / Draft RFC-0004 A3.

One complete paired A/D consumer and a fixed4096-cell public-grid A3.
"""
from dataclasses import dataclass
import struct
import norm_divisor as dv

r=dv.r
norm=dv.norm
need=r.need
PREFIX=b'stele/research/q26/norm-output-factors/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    exponent: int
    scaled: int
    divisor: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<32 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<30)*p.identity;ids=(p.source,p.exponent,p.scaled,p.divisor,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<30) for x in ids) and len(set(ids))==5,'Spec')
    paired=dv.Spec(p.schema,64*p.identity+1,p.source,p.exponent,p.scaled,p.divisor,p.repetitions);dv.derive(paired,d)
    s=p.schema;fn=dv.s.ex.fn;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQQQ',1,d,p.repetitions,p.identity,*ids)+fn.encode(function)
    return dict(paired=paired,base=base,raw=raw)


def words(schema,a):
    norm.constants(schema);need(type(a) is int and -23<=a<=9,'Exponent');e=schema.F+schema.G+21+a-schema.E
    divisor=1<<max(e,0);bias=(1<<(e-1)) if e>0 else 0;left=1<<max(-e,0)
    return [int(e<0),int(e>=0)]+list(divisor.to_bytes(16,'little')+bias.to_bytes(16,'little')+left.to_bytes(8,'little'))+[0]*22


def public_grid(schema):
    rows=[words(schema,i-23) for i in range(33)]+[[0]*64]*31
    return [row[j] for j in range(64) for row in rows]


def roots(p,proof):
    v=derive(p,4);r.vector(proof['factors'],64)
    return dv.roots(v['paired'],proof['paired'])+[r.root(p.output,proof['factors'])]


def expected_roots(p,n,a,scaled,divisor,factors):
    v=derive(p,4);r.vector(factors,64)
    return dv.expected_roots(v['paired'],n,a,scaled,divisor)+[r.root(p.output,factors)]


def parts(p,proof,d):
    v=derive(p,d);base=v['base'];indicator=proof['paired']['scaled']['exponent']['indicator']['words'];factors=proof['factors']
    r.vector(indicator,64);r.vector(factors,64)
    i=dict(id=(1<<26)*p.identity+(1<<25),m=12,k=0,ids=[base+8,base+9,base+10],terms=[(r.sc.scalar(1,d),[0,1]),(r.sc.scalar(-1,d),[0,2])])
    return i,[[r.sc.scalar(x,d) for x in xs] for xs in (indicator*64,[x for x in factors for _ in range(64)],public_grid(p.schema))]


def transcript(v,bound,state,d):
    need(type(bound) is list and len(bound)==5 and all(type(x) is bytes and len(x)==32 for x in bound+[state]),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound)+state,d)


def prepare(p,n,a,d):
    v=derive(p,d);return dv.prove(v['paired'],n,a,d),words(p.schema,a)


def assemble(p,pair,factors,d):
    """Producer only; actual paired sources and all parent claims still verify."""
    v=derive(p,d);r.vector(factors,64);proof=dict(paired=pair[0],factors=list(factors));t=transcript(v,roots(p,proof),pair[1],d)
    proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,n,a,d):
    return assemble(p,*prepare(p,n,a,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==5 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'paired','factors','zero'},'ProofShape');r.vector(proof['factors'],64)
    need(r.root(p.output,proof['factors'])==expected[4],'Factors:CommitmentMismatch')
    try:child=dv.verify(v['paired'],expected[:4],proof['paired'],d)
    except ValueError as error:raise ValueError('Paired:'+str(error)) from None
    part=proof['zero'];need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
        and type(part['rounds']) is list and len(part['rounds'])==12 and all(type(xs) is list and len(xs)==3 for xs in part['rounds'])
        and type(part['final']) is list and len(part['final'])==3 and all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
    t=transcript(v,expected,child['state'],d);i,tables=parts(p,proof,d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('Factors:'+str(error)) from None
    return dict(state=t.state,paired=child,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),
        account=dict(child['account'],range_reduction_numerator=child['account']['range_reduction_numerator']+sum(x['numerator'] for x in receipt['sc'])))
