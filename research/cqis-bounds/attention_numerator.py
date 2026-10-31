"""Draft RFC-0004 A3/A6 / RFC-0009 A2: scaled attention magnitude bytes.

Complete fixed channel groups preserve the range capacity at full width.
One faithful byte-column A3 consumes all four actual original views.
"""
from dataclasses import dataclass
import struct
import attention_normalization_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-numerator/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    a=(p.schema.width-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=(p.source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==2,'Spec')
    shift=max(p.schema.output_fraction-p.schema.fraction+p.schema.drop,0);q,rem=divmod(shift,8);c=1<<rem;T=constants['total_max'];U=constants['numerator_max']
    need(T<1<<64 and U==T<<shift and U<1<<128,'Capacity');need(2*(256*c-1)<r.sc.P,'FieldBound')
    bu=(max(1,(U.bit_length()+7)//8)-1).bit_length();groups=1 if n*(1<<bu)<=131072 else 2;group_n=n//groups
    caps={'source':(T,)*p.schema.width}
    for j in range(groups):
        real=min(group_n,p.schema.width-j*group_n);caps['output_'+str(j)]=(U,)*real+(0,)*(group_n-real if groups==2 else 0)
    for j in range(4):caps['carry_'+str(j)]=tuple(c-1 if i<p.schema.width and 4*j+k<15 else 0 for k in range(4) for i in range(n))
    ranges={name:r.Spec(256*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(caps.items(),1)}
    layouts={name:r.derive(child,d) for name,child in ranges.items()};bm=layouts['source'][1]
    need(layouts['source'][3]<=8 and all(layouts['output_'+str(j)][2:4]==(group_n,1<<bu) for j in range(groups)) and all(layouts['carry_'+str(j)][3]==1 for j in range(4)),'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(constants=constants,ranges=ranges,a=a,n=n,groups=groups,group_n=group_n,bm=bm,bu=bu,shift=shift,q=q,c=c,base=base,raw=raw)


def witness(p,ms):
    v=derive(p,4);need(type(ms) is list and len(ms)==p.schema.width and all(type(x) is int and 0<=x<=v['constants']['total_max'] for x in ms),'Input')
    us=[x<<v['shift'] for x in ms];w={'source':ms.copy()};size=v['group_n'];n=v['n'];padded=ms+[0]*(n-len(ms));carry=[0]*n;cs=[]
    for j in range(v['groups']):
        values=us[j*size:(j+1)*size];w['output_'+str(j)]=values+[0]*(size-len(values) if v['groups']==2 else 0)
    for k in range(16):
        carry=[(v['c']*(x>>(8*(k-v['q']))&255 if 0<=k-v['q']<8 else 0)+carry[i])//256 for i,x in enumerate(padded)];cs.extend(carry)
    for j in range(4):w['carry_'+str(j)]=cs[4*j*n:4*(j+1)*n]
    return w


def full(v,name,words,width):
    _,_,n,compact,_,_=r.derive(v['ranges'][name],4);r.vector(words,n*compact);need(compact<=width,'Capacity');return words+[0]*(n*(width-compact))


def output_words(v,proof):
    groups=[full(v,'output_'+str(j),proof['output_'+str(j)]['words'],16) for j in range(v['groups'])];size=v['group_n']
    return [x for k in range(16) for group in groups for x in group[k*size:(k+1)*size]]


def roots(p,proof):
    v=derive(p,4);return [r.root(p.source,full(v,'source',proof['source']['words'],8)),r.root(p.output,output_words(v,proof))]


def expected_roots(p,ms):
    v=derive(p,4);w=witness(p,ms)
    def planes(xs,width):return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(v['n']-len(xs))]
    return [r.root(p.source,planes(w['source'],8)),r.root(p.output,planes([x<<v['shift'] for x in ms],16))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];words=full(v,'source',proof['source']['words'],8);shifted=[];carry=[]
    # The whole source cap makes every omitted high source bit zero before
    # shifting. Both sides of each retained column are <=32767<p/2.
    for k in range(16):shifted.extend(words[(k-v['q'])*n:(k-v['q']+1)*n] if 0<=k-v['q']<8 else [0]*n)
    for j in range(4):xs=proof['carry_'+str(j)]['words'];r.vector(xs,4*n);carry.extend(xs)
    i=dict(id=1024*p.identity+128,m=v['a']+4,k=0,ids=[v['base']+j for j in range(16,20)],terms=[(r.sc.scalar(x,d),[j]) for j,x in enumerate((v['c'],1,-1,-256))])
    return [('Shift',i,[[r.sc.scalar(x,d) for x in row] for row in (shifted,[0]*n+carry[:-n],output_words(v,proof),carry)])]


def transcript(v,bound,states,d):
    count=len(v['ranges']);need(type(bound) is list and len(bound)==2+count and type(states) is list and len(states)==count and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,ms,d):
    v=derive(p,d);w=witness(p,ms);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; child states and coherent false columns grant no acceptance."""
    v=derive(p,d);names=tuple(v['ranges']);proof={name:pairs[name][0] for name in names};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in names],[pairs[name][1] for name in names],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,ms,d):
    return assemble(p,prepare(p,ms,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);names=tuple(v['ranges']);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(names)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(names) and type(proof['zero']) is list and len(proof['zero'])==1,'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for name,actual,target in zip(('Magnitude','Numerator'),roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    t=transcript(v,expected+[proof['roots'][name] for name in names],[child['state'] for child in children],d);_,i,tables=parts(p,proof,d)[0];part=proof['zero'][0]
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==4 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('Shift:'+str(error)) from None
    accounts=[child['account'] for child in children];records=receipt['sc']
    return dict(state=t.state,children=children,sc=records,claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
