"""RFC-0009 §2 step3 / Draft RFC-0004 A3: consumed masked probability sum.

O(N) byte views plus two complete ranges/lookups and one A1 sum. The independent
original MLE consumer is revealing reference work, not a native/private claim.
"""
from dataclasses import dataclass
import struct
import attention_maximum as attained

r=attained.r
need=r.need
PREFIX=b'stele/research/q26/attention-probability-sum/v1\0'
CHILDREN=('source','output')


@dataclass(frozen=True)
class Spec:
    row: attained.Spec
    exponent: int
    identity: int
    source: int
    output: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');mv=attained.derive(p.row,d)
    need(type(p.exponent) is int and 0<=p.exponent<=14 and type(p.identity) is int and 0<=p.identity<1<<48,'Spec');base=(1<<63)+(1<<14)*p.identity
    need(base+(1<<14)<=mv['base'] or mv['base']+(1<<14)<=base,'Spec');ids=tuple(getattr(p.row,name) for name in attained.ROLES)+(p.source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) and not mv['base']<=x<mv['base']+(1<<14) for x in ids) and len(set(ids))==6,'Spec')
    Q=1<<p.exponent;cap=sum(mv['allowed'])*Q;need(2*cap<r.sc.P,'FieldBound')
    ranges=dict(source=r.Spec(256*p.identity+1,p.source,tuple(Q*int(bit) for bit in mv['allowed']),p.row.repetitions),output=r.Spec(256*p.identity+2,base+1,(cap,),p.row.repetitions))
    bp=r.derive(ranges['source'],d)[1];bz=r.derive(ranges['output'],d)[1];need(bp<=1 and bz<=2,'Capacity')
    raw=PREFIX+struct.pack('<BBBBQQQI',1,d,p.row.repetitions,p.exponent,p.identity,p.source,p.output,len(mv['raw']))+mv['raw']
    return dict(ranges=ranges,Q=Q,cap=cap,a=mv['a'],n=mv['n'],count=mv['count'],allowed=mv['allowed'],bp=bp,bz=bz,base=base,raw=raw)


def witness(p,xs):
    v=derive(p,4);need(type(xs) is list and len(xs)==v['count'] and all(type(x) is int and 0<=x<=(v['Q'] if bit else 0) for x,bit in zip(xs,v['allowed'])),'Input')
    return dict(source=xs.copy(),output=[sum(xs)])


def full_output(v,words):
    r.vector(words,1<<v['bz']);return words+[0]*(4-len(words))


def roots(p,proof):
    v=derive(p,4);return [r.source_root(v['ranges']['source'],proof['source']['words']),r.root(p.output,full_output(v,proof['output']['words']))]


def expected_roots(p,xs):
    v=derive(p,4);w=witness(p,xs);return [r.source_root(v['ranges']['source'],r.witness(v['ranges']['source'],xs)[0]),r.root(p.output,list(w['output'][0].to_bytes(4,'little')))]


def part(p,proof,d):
    v=derive(p,d);n=v['n'];words=proof['source']['words'];r.vector(words,n*(1<<v['bp']));output=full_output(v,proof['output']['words']);total=sum(x<<(8*j) for j,x in enumerate(output))
    # Both complete ranges precede these field lifts; both sides are <=2^28<p/2.
    values=[sum(words[j*n+i]<<(8*j) for j in range(1<<v['bp'])) for i in range(n)]
    return dict(id=1024*p.identity+128,m=v['a'],ids=[v['base']+16],terms=[(r.sc.scalar(1,d),[0])],sum=r.sc.scalar(total,d)),[[r.sc.scalar(x,d) for x in values]]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==3 and type(states) is list and len(states)==2 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,d):
    v=derive(p,d);w=witness(p,xs);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; supplied range states confer no acceptance."""
    v=derive(p,d);proof={name:pairs[name][0] for name in CHILDREN};compact=r.source_root(v['ranges']['output'],proof['output']['words'])
    t=transcript(v,roots(p,proof)+[compact],[pairs[name][1] for name in CHILDREN],d);proof['sum']=r.sc.prove(t,*part(p,proof,d))[0]
    return proof,t.state


def prove(p,xs,d):
    return assemble(p,prepare(p,xs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(CHILDREN)|{'sum'},'ProofShape');ranges=[]
    try:ranges.append(r.verify(v['ranges']['source'],expected[0],proof['source'],d))
    except ValueError as error:raise ValueError('Source:'+str(error)) from None
    try:
        output=proof['output'];need(type(output) is dict and 'words' in output,'ProofShape');compact=r.source_root(v['ranges']['output'],output['words']);ranges.append(r.verify(v['ranges']['output'],compact,output,d))
        need(r.root(p.output,full_output(v,output['words']))==expected[1],'CommitmentMismatch')
    except ValueError as error:raise ValueError('Output:'+str(error)) from None
    t=transcript(v,expected+[compact],[child['state'] for child in ranges],d);i,tables=part(p,proof,d);s=proof['sum']
    need(type(s) is dict and set(s)=={'rounds','final'} and type(s['rounds']) is list and len(s['rounds'])==v['a'] and all(type(row) is list and len(row)==2 for row in s['rounds']) and type(s['final']) is list and len(s['final'])==1,'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in s['rounds']+[s['final']] for value in row),'NoncanonicalField')
    try:receipt=r.sc.verify_public(t,i,s,tables)
    except ValueError as error:raise ValueError('Sum:'+str(error)) from None
    accounts=[child['account'] for child in ranges]
    account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),sum_reduction_numerator=receipt['sc']['numerator'],denominator=r.sc.P**d)
    return dict(state=t.state,ranges=ranges,sc=[receipt['sc']],claims=receipt['claims'],draws=dict(t.draws),account=account)
