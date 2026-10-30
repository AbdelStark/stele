"""Q26/Q31 gated products: RFC-0004 §3 / Draft A3/A8, revealing research.

O(N) witness, views and folded A3 producer; inherited verifiers are reference.
"""
from dataclasses import dataclass
import struct
import gated_product_bounds as g
import signed_source as ss

r=ss.r
need=r.need
SIGNED=('left','right','output')
NAMES=SIGNED+('carry',)
AUX=('left_magnitude','right_magnitude','output_magnitude','carry')
PREFIX=b'stele/research/q26/gated-consumer/v1\0'
# Draft A3/A8: actual signed16 magnitude<=32768 implies high byte<=128.
# Cross column <=2*255*128+255; any result side <=255+256*255.
COLUMN_BOUND=65535


@dataclass(frozen=True)
class Spec:
    schema: g.Spec
    identity: int
    left: int
    right: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=g.constants(p.schema); count=p.schema.dimension; a=(count-1).bit_length(); n=1<<a; need(4*n<=4096,'Capacity')
    base=(1<<63)+(1<<18)*p.identity; external=(p.left,p.right,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    signed={name:ss.Spec(512*p.identity+j+1,source,base+j+1,bits,count,p.repetitions)
            for j,(name,source,bits) in enumerate(zip(SIGNED,external,(16,16,32)))}
    for child in signed.values(): ss.derive(child,d)
    carry=r.Spec(4096*p.identity+65,base+4,(255,)*(4*n),p.repetitions); r.derive(carry,d)
    need(2*COLUMN_BOUND<r.sc.P,'FieldBound')
    raw=PREFIX+struct.pack('<BBBQQQQIBB',1,d,p.repetitions,p.identity,p.left,p.right,p.output,count,p.schema.up_fraction,p.schema.silu_fraction)
    return dict(**signed,carry=carry,a=a,n=n,base=base,cert=cert,raw=raw)


def witness(p,xs,ys):
    v=derive(p,4); need(type(xs) is list and type(ys) is list,'Input'); g.inputs(p.schema,tuple(xs),tuple(ys)); n=v['n']
    output=[x*y for x,y in zip(xs,ys)]; left=[abs(x) for x in xs]+[0]*(n-len(xs)); right=[abs(y) for y in ys]+[0]*(n-len(ys))
    incoming=[0]*n; carry=[]
    for j in range(4):
        incoming=[(incoming[i]+sum((left[i]>>(8*k)&255)*(right[i]>>(8*(j-k))&255) for k in range(2) if 0<=j-k<2))//256 for i in range(n)]
        carry.extend(incoming)
    return dict(output=output,carry=carry)


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(ss.derive(v[name],4)['ranges'][0],proof[name]['ranges'][0]['words']) for name in SIGNED]


def bound(expected,proof):
    return expected+[proof['roots'][name] for name in AUX]


def parts(p,proof,d):
    v=derive(p,d); n,base=v['n'],v['base']; mags=[proof[name]['ranges'][1]['words'] for name in SIGNED]
    signs=[proof[name]['ranges'][2]['words'] for name in SIGNED]; carry=proof['carry']['words']
    for xs,size in zip(mags+signs+[carry],(2*n,2*n,4*n,2*n,2*n,2*n,4*n)): r.vector(xs,size)
    left,right,z=mags; zero=[0]*n
    rows=[left[:n]*2+left[n:]+zero,right[:n]+right[n:]*2+zero,zero+left[n:]+zero*2,zero+right[:n]+zero*2,
          zero+carry[:-n],z,carry]
    def item(name,index,m,ids,terms,values):
        return name,dict(id=16384*p.identity+512+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(x,d),factors) for x,factors in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in values]
    return [item('ProductColumns',0,v['a']+2,list(range(base+16,base+21))+[base+3,base+21],
                 [(1,[0,1]),(1,[2,3]),(1,[4]),(-1,[5]),(-256,[6])],rows),
            item('TerminalCarry',1,v['a'],[base+22],[(1,[0])],[carry[-n:]]),
            item('SignTransfer',2,v['a']+2,[base+23,base+24,base+25,base+3],
                 [(1,[0,3]),(1,[1,3]),(-2,[0,1,3]),(-1,[2,3])],[xs[:n]*4 for xs in signs]+[z])]


def transcript(p,bounds,states,d):
    need(type(bounds) is list and len(bounds)==7 and type(states) is list and len(states)==4 and
         all(type(x) is bytes and len(x)==32 for x in bounds+states),'Root')
    return r.scalar.Transcript(derive(p,d)['raw']+b''.join(bounds+states),d)


def prepare(p,xs,ys,d):
    v=derive(p,d); w=witness(p,xs,ys)
    return dict(**{name:ss.prove(v[name],values,d) for name,values in zip(SIGNED,(xs,ys,w['output']))},carry=r.prove(v['carry'],w['carry'],d))


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; only verify authorizes a statement."""
    v=derive(p,d); proof={name:pairs[name][0] for name in NAMES}
    proof['roots']={name+'_magnitude':r.root(v['base']+j+1,proof[name]['ranges'][1]['words']) for j,name in enumerate(SIGNED)}
    proof['roots']['carry']=r.source_root(v['carry'],proof['carry']['words'])
    t=transcript(p,bound(roots(p,proof),proof),[pairs[name][1] for name in NAMES],d)
    proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,xs,ys,d):
    return assemble(p,prepare(p,xs,ys,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(AUX),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root')
    need(type(proof['zero']) is list and len(proof['zero'])==3,'ProofShape'); children=[]
    targets=[[root,proof['roots'][name+'_magnitude']] for name,root in zip(SIGNED,expected)]+[proof['roots']['carry']]
    for name,target,verifier in zip(NAMES,targets,(ss.verify,ss.verify,ss.verify,r.verify)):
        try: children.append(verifier(v[name],target,proof[name],d))
        except ValueError as error: raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(p,bound(expected,proof),[child['state'] for child in children],d); records=[]; claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
             all(type(xs) is list and len(xs)==r.sc.degree(i)+1 for xs in part['rounds']) and
             type(part['final']) is list and len(part['final'])==len(i['ids']) and
             all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
        try: receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children]; carry=accounts[-1]
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),
                account=dict(identities=sum((x['identities'] for x in accounts[:3]),[])+[(carry['identity_numerator'],carry['identity_power'])],
                    lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
