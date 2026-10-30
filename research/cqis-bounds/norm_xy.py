"""RFC-0022 §2.3 xy / Draft RFC-0004 A3: consumed revealing research.

O(N) witness, views and folded A3 producer; complete inherited range consumers.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import signed_source as ss
import function_identity as fn

r=ss.r
need=r.need
NAMES=('left','right','output','carry')
AUX=('left_magnitude','right_magnitude','carry')
PREFIX=b'stele/research/q26/norm-xy/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    left: int
    right: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.d;a=(count-1).bit_length();n=1<<a;need(4*n<=4096,'Capacity')
    base=(1<<63)+(1<<18)*p.identity;external=(p.left,p.right,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    cert=norm.limbs.derive(norm.column_specs(p.schema)['xy'])
    need(cert['carry_caps']==(0,254,255,64,0) and max(cert['lhs']+cert['rhs'])==65535 and 2*65535<r.sc.P,'FieldBound')
    left=ss.Spec(512*p.identity+1,p.left,base+1,16,count,p.repetitions)
    right=ss.Spec(512*p.identity+2,p.right,base+2,16,count,p.repetitions)
    output=r.Spec(4096*p.identity+65,p.output,(1<<30,)*count,p.repetitions)
    caps=tuple(cap if i<count else 0 for cap in cert['carry_caps'][1:] for i in range(n))
    carry=r.Spec(4096*p.identity+66,base+4,caps,p.repetitions)
    for child in (left,right):ss.derive(child,d)
    for child in (output,carry):r.derive(child,d)
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQ',1,d,p.repetitions,p.identity,*external)+fn.encode(function)
    return dict(left=left,right=right,output=output,carry=carry,a=a,n=n,base=base,cert=cert,raw=raw)


def witness(p,xs,ys):
    v=derive(p,4);need(type(xs) is list and type(ys) is list,'Input');norm.inputs(p.schema,tuple(xs),tuple(ys));n=v['n']
    left=[abs(x) for x in xs]+[0]*(n-len(xs));right=[abs(y) for y in ys]+[0]*(n-len(ys));incoming=[0]*n;carry=[]
    for k in range(4):
        incoming=[(incoming[i]+sum((left[i]>>(8*j)&255)*(right[i]>>(8*(k-j))&255) for j in range(2) if 0<=k-j<2))//256 for i in range(n)]
        carry.extend(incoming)
    return dict(output=[abs(x*y) for x,y in zip(xs,ys)],carry=carry)


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(ss.derive(v[name],4)['ranges'][0],proof[name]['ranges'][0]['words']) for name in NAMES[:2]]+[r.source_root(v['output'],proof['output']['words'])]


def expected_roots(p,xs,ys,output):
    v=derive(p,4);bound=[]
    for name,values in zip(NAMES[:2],(xs,ys)):
        raw=ss.witness(v[name],values)[0];child=ss.derive(v[name],4)['ranges'][0];bound.append(r.source_root(child,r.witness(child,raw)[0]))
    need(type(output) is list and len(output)==p.schema.d and all(type(x) is int and 0<=x<1<<32 for x in output),'Output')
    padded=output+[0]*(v['n']-len(output));words=[x>>(8*j)&255 for j in range(4) for x in padded]
    return bound+[r.source_root(v['output'],words)]


def parts(p,proof,d):
    v=derive(p,d);n,base=v['n'],v['base'];left,right=[proof[name]['ranges'][1]['words'] for name in NAMES[:2]];z=proof['output']['words'];carry=proof['carry']['words']
    for xs,size in zip((left,right,z,carry),(2*n,2*n,4*n,4*n)):r.vector(xs,size)
    zero=[0]*n;rows=[left[:n]*2+left[n:]+zero,right[:n]+right[n:]*2+zero,zero+left[n:]+zero*2,zero+right[:n]+zero*2,zero+carry[:-n],z,carry]
    i=dict(id=16384*p.identity+512,m=v['a']+2,k=0,ids=list(range(base+16,base+21))+[p.output,base+21],
        terms=[(r.sc.scalar(x,d),factors) for x,factors in ((1,[0,1]),(1,[2,3]),(1,[4]),(-1,[5]),(-256,[6]))])
    return i,[[r.sc.scalar(x,d) for x in xs] for xs in rows]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==6 and type(states) is list and len(states)==4 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,ys,d):
    v=derive(p,d);w=witness(p,xs,ys)
    return dict(left=ss.prove(v['left'],xs,d),right=ss.prove(v['right'],ys,d),output=r.prove(v['output'],w['output'],d),carry=r.prove(v['carry'],w['carry'],d))


def assemble(p,pairs,d):
    """Producer only: every actual source/range/column remains mandatory in verify."""
    v=derive(p,d);proof={name:pairs[name][0] for name in NAMES}
    proof['roots']={name+'_magnitude':r.root(v['base']+j+1,proof[name]['ranges'][1]['words']) for j,name in enumerate(NAMES[:2])}
    proof['roots']['carry']=r.source_root(v['carry'],proof['carry']['words'])
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in AUX],[pairs[name][1] for name in NAMES],d)
    proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,xs,ys,d):
    return assemble(p,prepare(p,xs,ys,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(AUX),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root')
    targets=[[expected[j],proof['roots'][name+'_magnitude']] for j,name in enumerate(NAMES[:2])]+[expected[2],proof['roots']['carry']];children=[]
    for name,target,verifier in zip(NAMES,targets,(ss.verify,ss.verify,r.verify,r.verify)):
        try:children.append(verifier(v[name],target,proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    i,tables=parts(p,proof,d);part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m']
        and all(type(xs) is list and len(xs)==3 for xs in part['rounds']) and type(part['final']) is list and len(part['final'])==7 and all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
    t=transcript(v,expected+[proof['roots'][name] for name in AUX],[child['state'] for child in children],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('ProductColumns:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),
        account=dict(identities=sum((x['identities'] for x in accounts[:2]),[])+[(x['identity_numerator'],x['identity_power']) for x in accounts[2:]],
            lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in receipt['sc']),denominator=r.sc.P**d))
