"""Q26/Q31 dynamic scale: RFC-0004 §5.5 / Draft A3/A8, full-reveal research.

O(NB) attained-maximum work plus O(B) ceiling columns and actual range consumers.
"""
from dataclasses import dataclass
import struct
import attained_magnitude as am

r=am.r
need=r.need
NAMES=('maximum','scale','slack','carry')
PREFIX=b'stele/research/q26/dynamic-scale/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: am.row.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<40 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<22)*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<22) for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    maximum=am.Spec(p.schema,64*p.identity+1,p.source,base+1,p.repetitions); mv=am.derive(maximum,d)
    ranges={name:r.Spec(65536*p.identity+4096+j,source,caps,p.repetitions) for j,(name,source,caps) in enumerate(
        (('scale',p.output,(mv['cert']['scale_max'],)),('slack',base+2,(126,)),('carry',base+3,(127,)*mv['width'])))}
    for child in ranges.values(): r.derive(child,d)
    need(2*32893<r.sc.P,'FieldBound')
    raw=PREFIX+struct.pack('<BBBQQQBIB',1,d,p.repetitions,p.identity,p.source,p.output,int(p.schema.kind=='gated'),p.schema.dimension,p.schema.fraction)
    return dict(maximum=maximum,**ranges,a=mv['a'],b=mv['b'],width=mv['width'],base=base,cert=mv['cert'],raw=raw)


def witness(p,xs):
    v=derive(p,4); c=v['cert']; b=v['width']
    need(type(xs) is list and len(xs)==p.schema.dimension and all(type(x) is int and -c['source_max']<=x<=c['source_high'] for x in xs),'Input')
    maximum=max(abs(x) for x in xs); scale=(maximum+126)//127; slack=127*scale-maximum; incoming=0; carry=[]
    for j in range(b):
        numerator=127*(scale>>(8*j)&255)+incoming-(maximum>>(8*j)&255)-(slack if j==0 else 0)
        need(numerator%256==0,'Witness'); incoming=numerator//256; carry.append(incoming+1)
    return maximum,scale,slack,carry


def roots(p,proof):
    v=derive(p,4)
    return [am.roots(v['maximum'],proof['maximum'])[0],r.source_root(v['scale'],proof['scale']['words'])]


def parts(p,proof,d):
    v=derive(p,d); width,base=v['width'],v['base']
    maximum=proof['maximum']['maximum']['words']; scale=proof['scale']['words']; slack=proof['slack']['words']; carry=proof['carry']['words']
    for xs,size in ((maximum,width),(scale,width),(slack,1),(carry,width)): r.vector(xs,size)
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=262144*p.identity+32768+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(c,d),factors) for c,factors in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in rows]
    # Draft A3/A8: C may be -1. T=C+1 has public initial/terminal value1.
    return [item('ScaleCeiling',0,v['b'],[p.output,base+1,base+9,base+8,base+3],
                 [(127,[0]),(-1,[1]),(-1,[2]),(1,[3]),(-256,[4]),(255,[])],
                 [scale,maximum,slack+[0]*(width-1),[1]+carry[:-1],carry]),
            item('TerminalCarry',1,0,[base+10],[(1,[0]),(-1,[])],[carry[-1:]])]


def transcript(p,bound,states,d):
    need(type(bound) is list and len(bound)==5 and type(states) is list and len(states)==4 and
         all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(derive(p,d)['raw']+b''.join(bound+states),d)


def prepare(p,xs,d):
    v=derive(p,d); _,scale,slack,carry=witness(p,xs)
    return dict(maximum=am.prove(v['maximum'],xs,d),**{name:r.prove(v[name],values,d) for name,values in
                zip(NAMES[1:],([scale],[slack],carry))})


def assemble(p,pairs,d):
    """Arithmetic producer for supplied child proofs; full acceptance is verify."""
    v=derive(p,d); proof={name:pairs[name][0] for name in NAMES}; expected=roots(p,proof)
    proof.update(maximum_root=am.roots(v['maximum'],proof['maximum'])[1],
                 slack_root=r.source_root(v['slack'],proof['slack']['words']),carry_root=r.source_root(v['carry'],proof['carry']['words']))
    bound=[expected[0],proof['maximum_root'],expected[1],proof['slack_root'],proof['carry_root']]
    t=transcript(p,bound,[pairs[name][1] for name in NAMES],d)
    proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,xs,d):
    return assemble(p,prepare(p,xs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'maximum_root','slack_root','carry_root','zero'},'ProofShape')
    need(all(type(proof[k]) is bytes and len(proof[k])==32 for k in ('maximum_root','slack_root','carry_root')),'Root')
    need(type(proof['zero']) is list and len(proof['zero'])==2,'ProofShape')
    bound=[expected[0],proof['maximum_root'],expected[1],proof['slack_root'],proof['carry_root']]; children=[]
    for name,root,verifier in zip(NAMES,([expected[0],proof['maximum_root']],expected[1],proof['slack_root'],proof['carry_root']),(am.verify,r.verify,r.verify,r.verify)):
        try: children.append(verifier(v[name],root,proof[name],d))
        except ValueError as error: raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(p,bound,[child['state'] for child in children],d); records=[]; claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
             all(type(xs) is list and len(xs)==2 for xs in part['rounds']) and
             type(part['final']) is list and len(part['final'])==len(i['ids']) and
             all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
        try: receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children]; maximum=accounts[0]
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),
                account=dict(identities=maximum['identities']+[(x['identity_numerator'],x['identity_power']) for x in accounts[1:]],
                    lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),
                    selection_reduction_numerator=maximum['selection_reduction_numerator'],denominator=r.sc.P**d))
