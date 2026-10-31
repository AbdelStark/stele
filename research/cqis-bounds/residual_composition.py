"""Draft RFC-0004 A3/A8: complete single-round signed residual arithmetic.

O(N) root joins/output views and one A3 plus four complete child consumers.
Revealing canonical-u32 roots do not establish physical/model/private ownership.
"""
from dataclasses import dataclass
import struct
import residual_aligned as aligned
import residual_sign as sign
import residual_rounding as rounding
import signed_source as signed

residual=aligned.residual
r=aligned.r
need=r.need
NAMES=('left','right','offset','magnitude','sign','quotient','remainder','output')
MODULES=(('aligned',aligned,'Aligned'),('sign',sign,'NumeratorSign'),('rounding',rounding,'Rounding'),('output',signed,'Output'))
ROUTES=((0,1,2),(2,3,4),(3,5,6),(7,5))
PREFIX=b'stele/research/q26/residual-composition/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: residual.Spec
    identity: int
    left: int
    right: int
    offset: int
    magnitude: int
    sign: int
    quotient: int
    remainder: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');residual.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<42 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<20)*p.identity;ids=tuple(getattr(p,name) for name in NAMES);a=(p.schema.dimension-1).bit_length()
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<20) for x in ids) and len(set(ids))==8,'Spec')
    children=dict(aligned=aligned.Spec(p.schema,4*p.identity+1,p.left,p.right,p.offset,p.repetitions),
        sign=sign.Spec(p.schema,64*p.identity+1,p.offset,p.magnitude,p.sign,p.repetitions),
        rounding=rounding.Spec(p.schema,64*p.identity+2,p.magnitude,p.quotient,p.remainder,p.repetitions),
        output=signed.Spec(2048*p.identity+1,p.output,p.quotient,16,p.schema.dimension,p.repetitions))
    for name,module,_ in MODULES:module.derive(children[name],d)
    need(2*32768<r.sc.P,'FieldBound');s=p.schema
    raw=PREFIX+struct.pack('<BBB'+'Q'*9+'IBBB',1,d,p.repetitions,p.identity,*ids,s.dimension,s.left_fraction,s.right_fraction,s.output_fraction)
    return dict(**children,a=a,n=1<<a,base=base,raw=raw)


def witness(p,xs,ys):
    """Producer only; canonical evaluation never authorizes verification."""
    v=derive(p,4);need(type(xs) is list and type(ys) is list,'Input');residual.inputs(p.schema,tuple(xs),tuple(ys))
    offsets=aligned.witness(v['aligned'],xs,ys)['output'];sw=sign.witness(v['sign'],offsets)
    try:rw=rounding.witness(v['rounding'],sw['magnitude'])
    except ValueError as error:
        if str(error)=='QuotientRange':raise ValueError('OutputRange') from None
        raise
    zs=[(1-2*s)*q for s,q in zip(sw['sign'],rw['quotient'])];need(all(-32768<=z<=32767 for z in zs),'OutputRange')
    return dict(offset=offsets,magnitude=sw['magnitude'],sign=sw['sign'],quotient=rw['quotient'],remainder=rw['remainder'],output=zs)


def roots(p,proof):
    v=derive(p,4)
    return aligned.roots(v['aligned'],proof['aligned'])+sign.roots(v['sign'],proof['sign'])[1:]+rounding.roots(v['rounding'],proof['rounding'])[1:]+[r.root(p.output,proof['output']['ranges'][0]['words'])]


def expected_roots(p,xs,ys):
    v=derive(p,4);w=witness(p,xs,ys);sv=signed.derive(v['output'],4);raw,_,_,_=signed.witness(v['output'],w['output'])
    return aligned.expected_roots(v['aligned'],xs,ys,w['offset'])+sign.expected_roots(v['sign'],w['offset'],w['magnitude'],w['sign'])[1:]+rounding.expected_roots(v['rounding'],w['magnitude'],w['quotient'],w['remainder'])[1:]+[r.source_root(sv['ranges'][0],r.witness(sv['ranges'][0],raw)[0])]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];q=proof['rounding']['quotient']['words'];s=proof['sign']['sign']['words'];sz=proof['output']['ranges'][2]['words']
    for words,size in ((q,2*n),(s,n),(sz,2*n)):r.vector(words,size)
    rows=[[q[i]+256*q[n+i] for i in range(n)],s,sz[:n]]
    i=dict(id=65536*p.identity+32768,m=v['a'],k=0,ids=list(range(v['base']+16,v['base']+19)),terms=[(r.sc.scalar(1,d),[0,1]),(r.sc.scalar(-1,d),[0,2])])
    return i,[[r.sc.scalar(x,d) for x in row] for row in rows]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==8 and type(states) is list and len(states)==4 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,ys,d):
    v=derive(p,d);w=witness(p,xs,ys)
    return dict(aligned=aligned.prove(v['aligned'],xs,ys,d),sign=sign.prove(v['sign'],w['offset'],d),rounding=rounding.prove(v['rounding'],w['magnitude'],d),output=signed.prove(v['output'],w['output'],d))


def assemble(p,pairs,d):
    """Producer only; all complete children remain mandatory at zero output."""
    v=derive(p,d);proof={name:pairs[name][0] for name,_,_ in MODULES};t=transcript(v,roots(p,proof),[pairs[name][1] for name,_,_ in MODULES],d);proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,xs,ys,d):
    return assemble(p,prepare(p,xs,ys,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==8 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={name for name,_,_ in MODULES}|{'zero'},'ProofShape');children=[]
    for (name,module,label),indices in zip(MODULES,ROUTES):
        try:children.append(module.verify(v[name],[expected[i] for i in indices],proof[name],d))
        except ValueError as error:raise ValueError(label+':'+str(error)) from None
    i,tables=parts(p,proof,d);part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==3 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==3 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    t=transcript(v,expected,[child['state'] for child in children],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('SignedOutput:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=sum((item['identities'] for item in accounts),[]),lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in accounts),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in accounts)+sum(item['numerator'] for item in receipt['sc']),denominator=r.sc.P**d))
