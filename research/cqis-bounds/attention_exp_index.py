"""RFC-0021 §2.1 / Draft RFC-0004 A3: complete bytewise exponential indices.

Four full ranges and one A3 over4N; full source/view consumption is O(N).
This proves the split, not canonical table membership or exponential values.
"""
from dataclasses import dataclass
import struct
import attention_maximum as attained
import function_identity as fn

r=attained.r
need=r.need
PREFIX=b'stele/research/q26/attention-exp-index/v1\0'
ROLES=('difference','high','low')
CHILDREN=ROLES+('carry',)


@dataclass(frozen=True)
class Spec:
    row: attained.Spec
    representation: fn.Representation
    identity: int
    high: int
    low: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');mv=attained.derive(p.row,d)
    need(type(p.representation) is fn.Representation and type(p.representation.function) is fn.Function,'Representation');rep=p.representation;f=rep.function;f.__post_init__();rep.__post_init__()
    need((f.name,rep.mode) in (('exp_q/product',1),('exp_q/nearest',2)),'Representation');B,F,E=f.params[:3];k=f.params[3] if rep.mode==1 else rep.params[0]
    need((B,F)==(p.row.schema.domain_bits,p.row.schema.fraction),'FunctionScope')
    need(type(p.identity) is int and 0<=p.identity<1<<50,'Spec');base=(1<<63)+4096*p.identity
    need(base+4096<=mv['base'] or mv['base']+(1<<14)<=base,'Spec')
    ids=tuple(getattr(p.row,name) for name in attained.ROLES)+(p.high,p.low)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+4096 and not mv['base']<=x<mv['base']+(1<<14) for x in ids) and len(set(ids))==6,'Spec')
    n=mv['n'];count=mv['count'];allowed=mv['allowed'];coefficient=1<<(k%8);mask=tuple(int(b) for b in allowed)+(0,)*(n-count)
    limits=(mv['ranges']['difference'].caps,tuple((1<<(B-k))*int(b) for b in allowed),tuple(((1<<k)-1)*int(b) for b in allowed),tuple(coefficient*b for b in mask)*3+(0,)*n)
    sources=(p.row.difference,p.high,p.low,base+1);ranges={name:r.Spec(64*p.identity+index,source,cap,p.row.repetitions) for index,(name,source,cap) in enumerate(zip(CHILDREN,sources,limits),1)}
    widths=[r.derive(child,d)[3] for child in ranges.values()];need(widths[0]<=4 and max(widths[1:3])<=2 and widths[3]==1,'Capacity')
    need(2*(256*coefficient+255)<r.sc.P,'FieldBound')
    function=fn.encode(f);representation=fn.encode_representation(rep)
    raw=PREFIX+struct.pack('<BBBQQQI',1,d,p.row.repetitions,p.identity,p.high,p.low,len(mv['raw']))+mv['raw']+struct.pack('<H',len(function))+function+struct.pack('<H',len(representation))+representation
    return dict(ranges=ranges,a=mv['a'],n=n,count=count,allowed=allowed,cap=mv['bounds']['delta_max'],bu=widths[0].bit_length()-1,bh=widths[1].bit_length()-1,bl=widths[2].bit_length()-1,split=k,coefficient=coefficient,base=base,raw=raw)


def witness(p,us):
    v=derive(p,4);n=v['n'];count=v['count'];need(type(us) is list and len(us)==count and all(type(u) is int and 0<=u<=(v['cap'] if bit else 0) for u,bit in zip(us,v['allowed'])),'Input')
    high=[u>>v['split'] for u in us];low=[u% (1<<v['split']) for u in us];hs=high+[0]*(n-count);ls=low+[0]*(n-count);carry=[];incoming=[0]*n
    for j in range(4):
        index=j-v['split']//8;hb=[(h>>(8*index)&255) if 0<=index<2 else 0 for h in hs]
        incoming=[(v['coefficient']*h+(l>>(8*j)&255)+old)//256 for h,l,old in zip(hb,ls,incoming)];carry.extend(incoming)
    return dict(difference=us.copy(),high=high,low=low,carry=carry)


def roots(p,proof):
    v=derive(p,4);return [r.source_root(v['ranges'][name],proof[name]['words']) for name in ROLES]


def expected_roots(p,us):
    v=derive(p,4);w=witness(p,us);return [r.source_root(v['ranges'][name],r.witness(v['ranges'][name],w[name])[0]) for name in ROLES]


def part(p,proof,d):
    v=derive(p,d);n=v['n'];rows={}
    for name,child in v['ranges'].items():
        _,_,size,width,_,_=r.derive(child,d);r.vector(proof[name]['words'],size*width);rows[name]=proof[name]['words']
    h=rows['high'];width=1<<v['bh'];q=v['split']//8
    # Every selected byte belongs to the verified high source; outside bytes are public zero.
    shifted=[h[(j-q)*n+i] if 0<=j-q<width else 0 for j in range(4) for i in range(n)]
    low=rows['low']+[0]*(4*n-len(rows['low']));u=rows['difference']+[0]*(4*n-len(rows['difference']));carry=rows['carry']
    i=dict(id=256*p.identity+64,m=v['a']+2,k=0,ids=list(range(v['base']+16,v['base']+21)),terms=[(r.sc.scalar(value,d),[index]) for value,index in ((v['coefficient'],0),(1,1),(1,2),(-1,3),(-256,4))])
    return i,[[r.sc.scalar(x,d) for x in row] for row in (shifted,low,[0]*n+carry[:-n],u,carry)]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==4 and type(states) is list and len(states)==4 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,us,d):
    v=derive(p,d);w=witness(p,us);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; supplied range receipts do not authorize acceptance."""
    v=derive(p,d);proof={name:pairs[name][0] for name in CHILDREN};proof['carry_root']=r.source_root(v['ranges']['carry'],proof['carry']['words'])
    t=transcript(v,roots(p,proof)+[proof['carry_root']],[pairs[name][1] for name in CHILDREN],d);proof['zero']=r.zero_prove(t,*part(p,proof,d))
    return proof,t.state


def prove(p,us,d):
    return assemble(p,prepare(p,us,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(CHILDREN)|{'carry_root','zero'},'ProofShape');need(type(proof['carry_root']) is bytes and len(proof['carry_root'])==32,'Root');children=[]
    for (name,child),target in zip(v['ranges'].items(),expected+[proof['carry_root']]):
        try:children.append(r.verify(child,target,proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(v,expected+[proof['carry_root']],[child['state'] for child in children],d);i,tables=part(p,proof,d);z=proof['zero']
    need(type(z) is dict and set(z)=={'skip','rounds','final'} and type(z['skip']) is list and not z['skip'] and type(z['rounds']) is list and len(z['rounds'])==i['m'] and all(type(row) is list and len(row)==2 for row in z['rounds']) and type(z['final']) is list and len(z['final'])==5 and all(type(row) is list and len(row)==1 for row in z['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in z['rounds']+z['final'] for value in row),'NoncanonicalField')
    try:out,_=r.zc.verify(t,i,z,tables)
    except ValueError as error:raise ValueError('Index:'+str(error)) from None
    accounts=[child['account'] for child in children]
    account=dict(identities=[(item['identity_numerator'],item['identity_power']) for item in accounts],lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in accounts),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in accounts)+sum(row['numerator'] for row in out['sc']),denominator=r.sc.P**d)
    return dict(state=t.state,children=children,sc=out['sc'],claims=out['claims'],draws=dict(t.draws),account=account)
