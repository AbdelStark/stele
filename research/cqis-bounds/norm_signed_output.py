"""RFC-0022 §2.3 signed output / revealing Draft RFC-0004 A3.

O(N) output-sign views and A3, retaining complete canonical sign/signed sources.
Rounding must join the actual magnitude root; zero output never gates children.
"""
from dataclasses import dataclass
import struct
import norm_sign as ns
import signed_source as signed
import function_identity as fn

norm=ns.norm
r=ns.r
need=r.need
PREFIX=b'stele/research/q26/norm-signed-output/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    left: int
    right: int
    product: int
    sign: int
    output: int
    magnitude: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<40 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    a=(p.schema.d-1).bit_length();n=1<<a;base=(1<<63)+(1<<22)*p.identity;external=(p.left,p.right,p.product,p.sign,p.output,p.magnitude)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<22) for x in external) and len(set(external))==6,'Spec')
    sign=ns.Spec(p.schema,4*p.identity+1,p.left,p.right,p.product,p.sign,p.repetitions);output=signed.Spec(8192*p.identity+1,p.output,p.magnitude,16,p.schema.d,p.repetitions)
    ns.derive(sign,d);signed.derive(output,d);need(2*32768<r.sc.P,'FieldBound')
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQQQQ',1,d,p.repetitions,p.identity,*external)+fn.encode(function)
    return dict(sign=sign,output=output,a=a,n=n,base=base,raw=raw)


def inputs(p,xs,gs,ys):
    derive(p,4);need(type(xs) is list and type(gs) is list and type(ys) is list,'Input');norm.inputs(p.schema,tuple(xs),tuple(gs))
    need(len(ys)==p.schema.d and all(type(y) is int and -32768<=y<=32767 for y in ys),'Input')


def roots(p,proof):
    v=derive(p,4);sv=signed.derive(v['output'],4)
    return ns.roots(v['sign'],proof['sign'])+[r.source_root(sv['ranges'][j],proof['output']['ranges'][j]['words']) for j in range(2)]


def expected_roots(p,xs,gs,ys):
    v=derive(p,4);inputs(p,xs,gs,ys);sv=signed.derive(v['output'],4);raw,mag,_,_=signed.witness(v['output'],ys)
    signs=[int(bool(x and g) and (x<0)!=(g<0)) for x,g in zip(xs,gs)]
    return ns.expected_roots(v['sign'],xs,gs,[abs(x*g) for x,g in zip(xs,gs)],signs)+[r.source_root(child,r.witness(child,values)[0]) for child,values in zip(sv['ranges'][:2],(raw,mag))]


def views(p,proof):
    v=derive(p,4);n=v['n'];mag=proof['output']['ranges'][1]['words'];ysign=proof['output']['ranges'][2]['words'];flags=proof['sign']['flags']['words']
    for words,size in ((mag,2*n),(ysign,2*n),(flags,4*n)):r.vector(words,size)
    return [[mag[i]+256*mag[n+i] for i in range(n)],flags[2*n:3*n],ysign[:n]]


def parts(p,proof,d):
    v=derive(p,d);i=dict(id=262144*p.identity+131072,m=v['a'],k=0,ids=list(range(v['base']+16,v['base']+19)),terms=[(r.sc.scalar(1,d),[0,1]),(r.sc.scalar(-1,d),[0,2])])
    return i,[[r.sc.scalar(x,d) for x in row] for row in views(p,proof)]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==6 and type(states) is list and len(states)==2 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,gs,ys,d):
    v=derive(p,d);inputs(p,xs,gs,ys)
    return dict(sign=ns.prove(v['sign'],xs,gs,d),output=signed.prove(v['output'],ys,d))


def assemble(p,pairs,d):
    """Producer only; both complete children verify even when q is zero."""
    v=derive(p,d);proof={name:pairs[name][0] for name in ('sign','output')};t=transcript(v,roots(p,proof),[pairs[name][1] for name in ('sign','output')],d);proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,xs,gs,ys,d):
    return assemble(p,prepare(p,xs,gs,ys,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==6 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'sign','output','zero'},'ProofShape');children=[]
    for name,module,roots_,label in (('sign',ns,expected[:4],'ProductSign'),('output',signed,expected[4:],'Output')):
        try:children.append(module.verify(v[name],roots_,proof[name],d))
        except ValueError as error:raise ValueError(label+':'+str(error)) from None
    i,tables=parts(p,proof,d);part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==3 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==3 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    t=transcript(v,expected,[child['state'] for child in children],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('SignedOutput:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=sum((item['identities'] for item in accounts),[]),lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in accounts),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in accounts)+sum(item['numerator'] for item in receipt['sc']),denominator=r.sc.P**d))
