"""Draft RFC-0004 A3/A6 / RFC-0009 A2: biased attention magnitude bytes.

Complete channel groups and scalar denominator range precede one linear A3.
All five actual originals remain consumed, including the masked D broadcast.
"""
from dataclasses import dataclass
import struct
import attention_normalization_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-biased-numerator/v1\0'
FAMILIES=('numerator','biased')


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    numerator: int
    denominator: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');a=(p.schema.width-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=(p.numerator,p.denominator,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==3,'Spec')
    U,D,W=(constants[name] for name in ('numerator_max','denominator_max','biased_max'));need(W==2*U+D and max(U,D,W)<1<<128,'Capacity');need(2*767<r.sc.P,'FieldBound')
    exponent=lambda bound:(max(1,(bound.bit_length()+7)//8)-1).bit_length();bu,bw,bd=map(exponent,(U,W,D));groups={role:1 if n*(1<<b)<=131072 else 2 for role,b in zip(FAMILIES,(bu,bw))};caps={}
    for role,limit in zip(FAMILIES,(U,W)):
        count=groups[role];size=n//count
        for j in range(count):
            real=min(size,p.schema.width-j*size);caps[role+'_'+str(j)]=(limit,)*real+(0,)*(size-real if count==2 else 0)
    caps['denominator']=(D,)
    for j in range(4):caps['carry_'+str(j)]=tuple(2 if i<p.schema.width and 4*j+k<15 else 0 for k in range(4) for i in range(n))
    ranges={name:r.Spec(256*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(caps.items(),1)};layouts={name:r.derive(child,d) for name,child in ranges.items()}
    need(all(layouts[role+'_'+str(j)][2:4]==(n//groups[role],1<<b) for role,b in zip(FAMILIES,(bu,bw)) for j in range(groups[role])) and layouts['denominator'][3]<=16 and all(layouts['carry_'+str(j)][3]==1 for j in range(4)),'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(constants=constants,ranges=ranges,a=a,n=n,groups=groups,bu=bu,bw=bw,bd=bd,base=base,raw=raw)


def witness(p,us,D):
    v=derive(p,4);need(type(us) is list and len(us)==p.schema.width and all(type(x) is int and 0<=x<=v['constants']['numerator_max'] for x in us) and type(D) is int and 0<=D<=v['constants']['denominator_max'],'Input');ws=[2*x+D for x in us];w={};n=v['n']
    for role,values in zip(FAMILIES,(us,ws)):
        count=v['groups'][role];size=n//count
        for j in range(count):
            part=values[j*size:(j+1)*size];w[role+'_'+str(j)]=part+[0]*(size-len(part) if count==2 else 0)
    w['denominator']=[D];padded=us+[0]*(n-len(us));carry=[0]*n;cs=[]
    for k in range(16):
        carry=[(2*(x>>(8*k)&255)+(D>>(8*k)&255 if i<p.schema.width else 0)+carry[i])//256 for i,x in enumerate(padded)];cs.extend(carry)
    for j in range(4):w['carry_'+str(j)]=cs[4*j*n:4*(j+1)*n]
    return w


def full(v,proof,role):
    count=v['groups'][role];size=v['n']//count;groups=[]
    for j in range(count):
        name=role+'_'+str(j);compact=r.derive(v['ranges'][name],4)[3];words=proof[name]['words'];r.vector(words,size*compact);groups.append(words+[0]*(size*(16-compact)))
    return [x for k in range(16) for group in groups for x in group[k*size:(k+1)*size]]


def denominator_words(v,proof):
    width=r.derive(v['ranges']['denominator'],4)[3];words=proof['denominator']['words'];r.vector(words,width);return words+[0]*(16-width)


def roots(p,proof):
    v=derive(p,4);return [r.root(p.numerator,full(v,proof,'numerator')),r.root(p.denominator,denominator_words(v,proof)),r.root(p.output,full(v,proof,'biased'))]


def expected_roots(p,us,D):
    v=derive(p,4);witness(p,us,D)
    def planes(xs):return [x>>(8*k)&255 for k in range(16) for x in xs+[0]*(v['n']-len(xs))]
    return [r.root(p.numerator,planes(us)),r.root(p.denominator,list(D.to_bytes(16,'little'))),r.root(p.output,planes([2*x+D for x in us]))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];den=denominator_words(v,proof);carry=[]
    for j in range(4):xs=proof['carry_'+str(j)]['words'];r.vector(xs,4*n);carry.extend(xs)
    # Expected padding masks the shared scalar; every column side is <=767.
    rows=(full(v,proof,'numerator'),[den[k] if i<p.schema.width else 0 for k in range(16) for i in range(n)],[0]*n+carry[:-n],full(v,proof,'biased'),carry)
    i=dict(id=1024*p.identity+128,m=v['a']+4,k=0,ids=[v['base']+j for j in range(16,21)],terms=[(r.sc.scalar(x,d),[j]) for j,x in enumerate((2,1,1,-1,-256))])
    return [('Bias',i,[[r.sc.scalar(x,d) for x in row] for row in rows])]


def transcript(v,bound,states,d):
    count=len(v['ranges']);need(type(bound) is list and len(bound)==3+count and type(states) is list and len(states)==count and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root');return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,us,D,d):
    v=derive(p,d);w=witness(p,us,D);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; complete source joins, ranges and originals remain mandatory."""
    v=derive(p,d);names=tuple(v['ranges']);proof={name:pairs[name][0] for name in names};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in names],[pairs[name][1] for name in names],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)];return proof,t.state


def prove(p,us,D,d):
    return assemble(p,prepare(p,us,D,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);names=tuple(v['ranges']);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(names)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(names) and type(proof['zero']) is list and len(proof['zero'])==1,'ProofShape');need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for name,actual,target in zip(('Numerator','Denominator','Biased'),roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    t=transcript(v,expected+[proof['roots'][name] for name in names],[child['state'] for child in children],d);_,i,tables=parts(p,proof,d)[0];part=proof['zero'][0]
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==5 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('Bias:'+str(error)) from None
    accounts=[child['account'] for child in children];records=receipt['sc'];return dict(state=t.state,children=children,sc=records,claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
