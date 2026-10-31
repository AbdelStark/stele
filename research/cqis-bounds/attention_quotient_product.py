"""Draft RFC-0004 A3/A6 / RFC-0009 A2: attention quotient product bytes.

Complete quotient, product, denominator and two-byte carry ranges precede A3.
The degree-two relation consumes all seven actual source views.
"""
from dataclasses import dataclass
import struct
import attention_normalization_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-quotient-product/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    quotient: int
    denominator: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');a=(p.schema.width-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=(p.quotient,p.denominator,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==3,'Spec')
    D,P=(constants[name] for name in ('denominator_max','scaled_quotient_max'));need(P==32768*D and max(D,P)<1<<128,'Capacity');need(2*130815<r.sc.P,'FieldBound')
    exponent=lambda bound:(max(1,(bound.bit_length()+7)//8)-1).bit_length();bp,bd=map(exponent,(P,D));groups=1 if n*(1<<bp)<=131072 else 2;size=n//groups;caps={'quotient':(32768,)*p.schema.width}
    for j in range(groups):
        real=min(size,p.schema.width-j*size);caps['product_'+str(j)]=(P,)*real+(0,)*(size-real if groups==2 else 0)
    caps['denominator']=(D,)
    for j in range(4):caps['carry_'+str(j)]=tuple(510 if i<p.schema.width and 4*j+k<15 else 0 for k in range(4) for i in range(n))
    ranges={name:r.Spec(256*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(caps.items(),1)};layouts={name:r.derive(child,d) for name,child in ranges.items()}
    need(layouts['quotient'][2:4]==(n,2) and all(layouts['product_'+str(j)][2:4]==(size,1<<bp) for j in range(groups)) and layouts['denominator'][3]<=16 and all(layouts['carry_'+str(j)][2:4]==(4*n,2) for j in range(4)),'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(constants=constants,ranges=ranges,a=a,n=n,groups=groups,bp=bp,bd=bd,base=base,raw=raw)


def witness(p,qs,D):
    v=derive(p,4);need(type(qs) is list and len(qs)==p.schema.width and all(type(x) is int and 0<=x<=32768 for x in qs) and type(D) is int and 0<=D<=v['constants']['denominator_max'],'Input');products=[x*D for x in qs];w={'quotient':qs.copy()};n=v['n'];size=n//v['groups']
    for j in range(v['groups']):
        part=products[j*size:(j+1)*size];w['product_'+str(j)]=part+[0]*(size-len(part) if v['groups']==2 else 0)
    w['denominator']=[D];padded=qs+[0]*(n-len(qs));carry=[0]*n;cs=[]
    for k in range(16):
        current=D>>(8*k)&255;previous=D>>(8*(k-1))&255 if k else 0;carry=[((q&255)*current+(q>>8)*previous+carry[i])//256 for i,q in enumerate(padded)];cs.extend(carry)
    for j in range(4):w['carry_'+str(j)]=cs[4*j*n:4*(j+1)*n]
    return w


def full(v,proof):
    size=v['n']//v['groups'];groups=[]
    for j in range(v['groups']):
        name='product_'+str(j);compact=r.derive(v['ranges'][name],4)[3];words=proof[name]['words'];r.vector(words,size*compact);groups.append(words+[0]*(size*(16-compact)))
    return [x for k in range(16) for group in groups for x in group[k*size:(k+1)*size]]


def denominator_words(v,proof):
    width=r.derive(v['ranges']['denominator'],4)[3];words=proof['denominator']['words'];r.vector(words,width);return words+[0]*(16-width)


def carry_values(v,proof):
    size=4*v['n'];carry=[]
    for j in range(4):
        words=proof['carry_'+str(j)]['words'];r.vector(words,2*size);carry.extend(words[i]+256*words[size+i] for i in range(size))
    return carry


def roots(p,proof):
    v=derive(p,4);words=proof['quotient']['words'];r.vector(words,2*v['n']);return [r.root(p.quotient,words),r.root(p.denominator,denominator_words(v,proof)),r.root(p.output,full(v,proof))]


def expected_roots(p,qs,D):
    v=derive(p,4);witness(p,qs,D)
    def planes(xs,width):return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(v['n']-len(xs))]
    return [r.root(p.quotient,planes(qs,2)),r.root(p.denominator,list(D.to_bytes(16,'little'))),r.root(p.output,planes([x*D for x in qs],16))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];den=denominator_words(v,proof);carry=carry_values(v,proof);q=proof['quotient']['words'];r.vector(q,2*n)
    # Draft A6: both verified carry bytes reconstruct a value <=510. Each
    # independent column side is <=130815; no whole-field product is used.
    rows=(q[:n]*16,q[n:]*16,[x for byte in den for x in [byte]*n],[0]*n+[x for byte in den[:-1] for x in [byte]*n],[0]*n+carry[:-n],full(v,proof),carry)
    i=dict(id=1024*p.identity+128,m=v['a']+4,k=0,ids=[v['base']+j for j in range(16,23)],terms=[(r.sc.scalar(coefficient,d),factors) for coefficient,factors in ((1,[0,2]),(1,[1,3]),(1,[4]),(-1,[5]),(-256,[6]))])
    return [('Product',i,[[r.sc.scalar(x,d) for x in row] for row in rows])]


def transcript(v,bound,states,d):
    count=len(v['ranges']);need(type(bound) is list and len(bound)==3+count and type(states) is list and len(states)==count and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root');return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,qs,D,d):
    v=derive(p,d);w=witness(p,qs,D);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; complete source joins, ranges and originals are required."""
    v=derive(p,d);names=tuple(v['ranges']);proof={name:pairs[name][0] for name in names};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in names],[pairs[name][1] for name in names],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)];return proof,t.state


def prove(p,qs,D,d):
    return assemble(p,prepare(p,qs,D,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);names=tuple(v['ranges']);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(names)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(names) and type(proof['zero']) is list and len(proof['zero'])==1,'ProofShape');need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for name,actual,target in zip(('Quotient','Denominator','Product'),roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    t=transcript(v,expected+[proof['roots'][name] for name in names],[child['state'] for child in children],d);_,i,tables=parts(p,proof,d)[0];part=proof['zero'][0]
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==7 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('Product:'+str(error)) from None
    accounts=[child['account'] for child in children];records=receipt['sc'];return dict(state=t.state,children=children,sc=records,claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
