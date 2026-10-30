"""Q26/Q31 paired RMSNorm sources: RFC-0022 §2.3, Draft RFC-0004 A3.

Complete scaled consumer plus one dimension10 A3 over fixed-size byte views.
"""
from dataclasses import dataclass
import struct
import norm_scaled as s

norm=s.norm
r=s.r
need=r.need
PREFIX=b'stele/research/q26/norm-divisor/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    exponent: int
    scaled: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<38 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=norm.constants(p.schema); need(0<cert['D_max']<1<<124,'FieldBound'); base=(1<<63)+(1<<24)*p.identity
    ids=(p.source,p.exponent,p.scaled,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<24) for x in ids) and len(set(ids))==4,'Spec')
    scaled=s.Spec(p.schema,64*p.identity+1,p.source,p.exponent,p.scaled,p.repetitions); s.derive(scaled,d)
    n=p.schema; function=s.ex.fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',n.d,n.F,n.G,n.E,n.en,n.ed))
    raw=PREFIX+struct.pack('<BBBQQQQQ',1,d,p.repetitions,p.identity,*ids)+s.ex.fn.encode(function)
    return dict(scaled=scaled,cert=cert,base=base,raw=raw)


def public_grid(schema):
    """RFC-0022 §2.3: all configured divisor bytes; no witness-selected public table."""
    p=norm.constants(schema)['P']
    return [(p<<(2*max(i-23,0)))>>(8*j)&255 if i<33 else 0 for j in range(16) for i in range(64)]


def witness(p,a):
    v=derive(p,4); need(type(a) is int and -23<=a<=9,'Exponent')
    return list((v['cert']['P']*4**max(a,0)).to_bytes(16,'little'))


def roots(p,proof):
    """Arithmetic root construction, without conferring acceptance on supplied proofs."""
    v=derive(p,4); sv=s.derive(v['scaled'],4); lower=proof['scaled']; digits=lower['product']['input']['digits']
    er=s.ex.roots(sv['exponent'],lower['exponent']['offset'],lower['exponent']['factors']); r.vector(proof['divisor'],16)
    return [r.root(p.source,s.numerator_source(sv,digits)),er[0],s.lp.cr.source_root(sv['layout']['output'],lower['product']['output']['words']),
            r.root(p.output,proof['divisor'])]


def expected_roots(p,n,a,scaled,divisor):
    v=derive(p,4); need(type(divisor) is int and 0<divisor<=v['cert']['D_max'],'Divisor')
    return s.expected_roots(v['scaled'],n,a,scaled)+[r.root(p.output,list(divisor.to_bytes(16,'little')))]


def parts(p,proof,d):
    v=derive(p,d); base=v['base']; indicator=proof['scaled']['exponent']['indicator']['words']; words=proof['divisor']
    r.vector(indicator,64); r.vector(words,16)
    i=dict(id=(1<<20)*p.identity+(1<<19),m=10,k=0,ids=[base+8,base+9,base+10],
           terms=[(r.sc.scalar(1,d),[0,1]),(r.sc.scalar(-1,d),[0,2])])
    return i,[[r.sc.scalar(x,d) for x in xs] for xs in (indicator*16,[x for x in words for _ in range(64)],public_grid(p.schema))]


def transcript(v,bound,state,d):
    need(type(bound) is list and len(bound)==4 and all(type(x) is bytes and len(x)==32 for x in bound+[state]),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound)+state,d)


def prepare(p,n,a,d):
    v=derive(p,d); words=witness(p,a)
    return s.prove(v['scaled'],n,a,d),words


def assemble(p,pair,words,d):
    """Arithmetic producer; full child and final-claim consumers remain in verify."""
    v=derive(p,d); r.vector(words,16); proof=dict(scaled=pair[0],divisor=list(words)); t=transcript(v,roots(p,proof),pair[1],d)
    proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,n,a,d):
    return assemble(p,*prepare(p,n,a,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==4 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'scaled','divisor','zero'},'ProofShape'); r.vector(proof['divisor'],16)
    need(r.root(p.output,proof['divisor'])==expected[3],'Divisor:CommitmentMismatch')
    try: child=s.verify(v['scaled'],expected[:3],proof['scaled'],d)
    except ValueError as error: raise ValueError('Scaled:'+str(error)) from None
    part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
         and type(part['rounds']) is list and len(part['rounds'])==10 and all(type(xs) is list and len(xs)==3 for xs in part['rounds'])
         and type(part['final']) is list and len(part['final'])==3 and all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
    t=transcript(v,expected,child['state'],d); i,tables=parts(p,proof,d)
    try: receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error: raise ValueError('Divisor:'+str(error)) from None
    return dict(state=t.state,scaled=child,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),
                account=dict(child['account'],range_reduction_numerator=child['account']['range_reduction_numerator']+sum(x['numerator'] for x in receipt['sc'])))
