"""Q26/Q31 wide unsigned ranges: Draft RFC-0004 A3, consumed A3/lookup research."""
from collections import Counter
from dataclasses import dataclass
import struct
import capped_range as scalar

sc=scalar.sc
zc=scalar.zc
lu=scalar.lu
need=scalar.need
vector=scalar.vector
root=scalar.root
zero_prove=scalar.zero_prove
TABLE=scalar.TABLE
PREFIX=b'stele/research/q26/wide-range/v1\0'


@dataclass(frozen=True)
class Spec:
    identity: int
    source: int
    caps: tuple
    repetitions: int


def derive(p,d):
    need(2*scalar.COLUMN_BOUND<sc.P,'FieldBound')
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<56 and type(p.source) is int and 2<=p.source<1<<64,'Spec')
    need(type(p.repetitions) is int and p.repetitions in (1,2) and type(p.caps) is tuple and p.caps,'Spec')
    need(len(p.caps)<=65536,'Capacity')
    need(all(type(v) is int and 0<=v<1<<160 for v in p.caps),'Spec')
    a=(len(p.caps)-1).bit_length(); n=1<<a
    size=max(1,(max(p.caps).bit_length()+7)//8); b=(size-1).bit_length(); width=1<<b
    # Draft A3: more narrow words retain the existing maximum byte/lookup domain.
    need(n*width<=131072,'Capacity')
    base=(1<<63)+64*p.identity; need(not base<=p.source<base+64,'Spec')
    raw=PREFIX+struct.pack('<BBBQQI',1,d,p.repetitions,p.identity,p.source,len(p.caps))
    raw+=b''.join(v.to_bytes(20,'little') for v in p.caps)+scalar.table.table_id(TABLE)
    return a,b,n,width,base,raw


def source_root(p,words):
    _,_,n,width,_,_=derive(p,4); vector(words,n*width)
    return root(p.source,words)


def lookup_plan(p,d):
    a,b,n,width,base,_=derive(p,d)
    # Static 2BN<=262144<p: one ordinary characteristic-safe lookup unit.
    return dict(id=p.identity,m=a+b+1,b=a+b+1,r=p.repetitions,sources=(base,),
                mus=tuple(base+2+j for j in range(p.repetitions)),
                table=scalar.table.canonical_rows(TABLE),sigma=(1,)*(2*n*width))


def witness(p,values):
    _,_,n,width,_,_=derive(p,4)
    need(type(values) is list and len(values)==len(p.caps) and
         all(type(v) is int and 0<=v<=cap for v,cap in zip(values,p.caps)),'Range')
    values=values+[0]*(n-len(values)); caps=list(p.caps)+[0]*(n-len(p.caps))
    slack=[cap-x for cap,x in zip(caps,values)]
    bs=[x>>(8*j)&255 for xs in (values,slack) for j in range(width) for x in xs]
    cs=[]; carry=[0]*n
    for j in range(width):
        carry=[(bs[j*n+i]+bs[(width+j)*n+i]+carry[i])//256 for i in range(n)]; cs.extend(carry)
    return bs[:width*n],bs,cs


def parts(p,words,bs,cs,d):
    a,b,n,width,base,_=derive(p,d); count=n*width
    for xs,size in ((words,count),(bs,2*count),(cs,count)): vector(xs,size)
    caps=list(p.caps)+[0]*(n-len(p.caps)); fields=lambda xs:[sc.scalar(v,d) for v in xs]
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=4*p.identity+index,m=m,k=0,ids=ids,
            terms=[(sc.scalar(c,d),factors) for c,factors in terms]),[fields(xs) for xs in rows]
    return [item('SourceCopy',0,a+b,[p.source,base+8],[(1,[0]),(-1,[1])],[words,bs[:count]]),
            item('CapRelation',1,a+b,[base+8,base+17,base+18,base+1,base+19],
                 [(1,[0]),(1,[1]),(1,[2]),(-256,[3]),(-1,[4])],
                 [bs[:count],bs[count:],[0]*n+cs[:count-n],cs,
                  [cap>>(8*j)&255 for j in range(width) for cap in caps]]),
            item('CarryBoolean',2,a+b,[base+1],[(1,[0,0]),(-1,[0])],[cs]),
            item('TerminalCarry',3,a,[base+21],[(1,[0])],[cs[count-n:]])]


def transcript(p,expected,proof,d,lookup_state):
    return scalar.Transcript(derive(p,d)[-1]+expected+proof['byte_root']+proof['carry_root']+lookup_state,d)


def assemble(p,words,bs,cs,d):
    """Arithmetic producer for canonical supplied vectors; verifier enforces relations."""
    instances=parts(p,words,bs,cs,d); base=derive(p,d)[4]
    lookup,receipt=lu.prove(lookup_plan(p,d),[bs],d)
    proof=dict(byte_root=root(base,bs),carry_root=root(base+1,cs),words=list(words),carry=list(cs),lookup=lookup,zero=[])
    t=transcript(p,source_root(p,words),proof,d,receipt['state'])
    proof['zero']=[zero_prove(t,i,rows) for _,i,rows in instances]
    return proof,t.state


def prove(p,values,d):
    derive(p,d)
    return assemble(p,*witness(p,values),d)


def verify(p,expected,proof,d):
    _,_,n,width,base,_=derive(p,d); count=n*width
    need(type(expected) is bytes and len(expected)==32,'Root')
    need(type(proof) is dict and set(proof)=={'byte_root','carry_root','words','carry','lookup','zero'},'ProofShape')
    need(all(type(proof[k]) is bytes and len(proof[k])==32 for k in ('byte_root','carry_root')),'Root')
    need(type(proof['zero']) is list and len(proof['zero'])==4 and type(proof['lookup']) is dict,'ProofShape')
    source=proof['lookup'].get('sources'); need(type(source) is list and len(source)==1,'ProofShape'); bs=source[0]
    words,cs=proof['words'],proof['carry']
    for xs,size in ((words,count),(bs,2*count),(cs,count)): vector(xs,size)
    need(root(p.source,words)==expected and root(base,bs)==proof['byte_root'] and root(base+1,cs)==proof['carry_root'],'CommitmentMismatch')
    lookup=lu.verify(lookup_plan(p,d),[proof['byte_root']],proof['lookup'],d)
    t=transcript(p,expected,proof,d,lookup['state']); records=[]; claims=[]
    for (name,i,tables),part in zip(parts(p,words,bs,cs,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
             all(type(row) is list and len(row)==sc.degree(i)+1 for row in part['rounds']) and
             type(part['final']) is list and len(part['final'])==len(i['ids']) and
             all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        try: receipt,_=zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    account=lookup['account']
    return dict(state=t.state,lookup_state=lookup['state'],lookup_claims=lookup['claims'],
                lookup_draws=dict(Counter(label for tag,label in lookup['events'] if tag==1)),
                claims=claims,sc=records,draws=dict(t.draws),
                account=dict(identity_numerator=account['identity_numerator'],identity_power=account['identity_power'],
                    lookup_reduction_numerator=account['reduction_numerator'],range_reduction_numerator=sum(v['numerator'] for v in records),
                    denominator=account['denominator']))
