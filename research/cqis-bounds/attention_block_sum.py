"""Draft RFC-0004 A3/A6 / RFC-0009 A2: consumed signed rounded block totals.

Linear byte/root joins and one degree-two A1 retain both actual originals.
Static integer bounds precede channel batching; no signed intermediate cut.
"""
from dataclasses import dataclass
import struct
import attention_block_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-block-sum/v1\0'
NAMES=('sign','quotient','output')


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    blocks: tuple
    identity: int
    sign_sources: tuple
    quotient: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.blocks) is tuple and 1<=len(p.blocks)<=constants['block_count_max'] and all(type(x) is int and 0<=x<=constants['block_id_max'] for x in p.blocks) and all(x<y for x,y in zip(p.blocks,p.blocks[1:])),'Spec')
    need(type(p.sign_sources) is tuple and len(p.sign_sources)==len(p.blocks),'Spec');count=len(p.blocks)*p.schema.width;need(count<=16384,'Capacity');a=(count-1).bit_length();ac=(p.schema.width-1).bit_length();n,nc=1<<a,1<<ac;base=(1<<63)+(1<<14)*p.identity;ids=p.sign_sources+(p.quotient,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==len(ids),'Spec')
    G=constants['total_max'];need(8*G<r.sc.P,'FieldBound')
    caps=[(1,)*count,(constants['rounded_max'],)*count,(2*G,)*p.schema.width]
    ranges={name:r.Spec(256*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(zip(NAMES,caps),1)}
    for name,limit in zip(NAMES,(1,2,8)):need(r.derive(ranges[name],d)[3]<=limit,'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQII',1,d,p.repetitions,p.identity,len(p.blocks),len(encoded))+encoded
    raw+=b''.join(struct.pack('<I',block) for block in p.blocks)+b''.join(struct.pack('<Q',identity) for identity in ids)
    return dict(constants=constants,G=G,ranges=ranges,count=count,a=a,ac=ac,n=n,nc=nc,blocks=len(p.blocks),base=base,raw=raw)


def witness(p,flags,quotients):
    v=derive(p,4);need(type(flags) is list and len(flags)==v['count'] and all(type(x) is int and x in (0,1) for x in flags),'Input')
    need(type(quotients) is list and len(quotients)==v['count'] and all(type(x) is int and 0<=x<=v['constants']['rounded_max'] for x in quotients),'Input')
    width=p.schema.width;outputs=[v['G']+sum((1-2*flags[j*width+c])*quotients[j*width+c] for j in range(v['blocks'])) for c in range(width)]
    return dict(sign=flags.copy(),quotient=quotients.copy(),output=outputs)


def full(v,name,words,width):
    _,_,n,compact,_,_=r.derive(v['ranges'][name],4);r.vector(words,n*compact);need(compact<=width,'Capacity');return words+[0]*(n*(width-compact))


def sign_roots(p,v,words):
    r.vector(words,v['n']);width=p.schema.width
    return [r.root(identity,words[j*width:(j+1)*width]+[0]*(v['nc']-width)) for j,identity in enumerate(p.sign_sources)]


def roots(p,proof):
    v=derive(p,4);return sign_roots(p,v,proof['sign']['words'])+[r.root(p.quotient,full(v,'quotient',proof['quotient']['words'],2)),r.root(p.output,full(v,'output',proof['output']['words'],8))]


def expected_roots(p,flags,quotients):
    v=derive(p,4);w=witness(p,flags,quotients)
    def planes(xs,n,width):return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(n-len(xs))]
    return sign_roots(p,v,flags+[0]*(v['n']-v['count']))+[r.root(p.quotient,planes(quotients,v['n'],2)),r.root(p.output,planes(w['output'],v['nc'],8))]


def part(p,proof,point,d):
    v=derive(p,d);sc=r.sc;weights=r.scalar.eq_weights(point,d);n,nc=v['n'],v['nc'];bs=proof['sign']['words'];r.vector(bs,n);qs=full(v,'quotient',proof['quotient']['words'],2);us=full(v,'output',proof['output']['words'],8);zero=sc.scalar(0,d)
    # Both sources are actual linear views. The verifier never forms b*q.
    weighted=[sc.mul(weights[i%p.schema.width],sc.scalar(qs[i]+256*qs[n+i],d)) if i<v['count'] else zero for i in range(n)]
    # Integer channel differences are faithful before the random projection:
    # U+2*sum(b*q)=G+sum(q) has nonnegative sides <=4G<p/2.
    target=r.zc.total((sc.mul(weights[c],sc.scalar(sum(us[k*nc+c]<<(8*k) for k in range(8))-(v['G'] if c<p.schema.width else 0),d)) for c in range(nc)),d)
    return dict(id=1024*p.identity+128,m=v['a'],ids=[v['base']+16,v['base']+17],terms=[(sc.scalar(1,d),[0]),(sc.scalar(-2,d),[0,1])],sum=target),[weighted,[sc.scalar(x,d) for x in bs]]


def transcript(v,external,aux,states,d):
    need(type(external) is list and len(external)==v['blocks']+2 and type(aux) is list and len(aux)==3 and type(states) is list and len(states)==3 and all(type(x) is bytes and len(x)==32 for x in external+aux+states),'Root')
    t=r.scalar.Transcript(v['raw']+b''.join(external+aux+states),d);return t,[r.sc.challenge(t) for _ in range(v['ac'])]


def prepare(p,flags,quotients,d):
    v=derive(p,d);w=witness(p,flags,quotients);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; complete child verification supplies authoritative states."""
    v=derive(p,d);proof={name:pairs[name][0] for name in NAMES};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t,point=transcript(v,roots(p,proof),[proof['roots'][name] for name in NAMES],[pairs[name][1] for name in NAMES],d);proof['sum']=r.sc.prove(t,*part(p,proof,point,d))[0];return proof,t.state


def prove(p,flags,quotients,d):
    return assemble(p,prepare(p,flags,quotients,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==v['blocks']+2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','sum'} and type(proof['roots']) is dict and set(proof['roots'])==set(NAMES),'ProofShape');need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for name,actual,target in zip(['Sign:'+str(block) for block in p.blocks]+['Quotient','Output'],roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    s=proof['sum'];need(type(s) is dict and set(s)=={'rounds','final'} and type(s['rounds']) is list and len(s['rounds'])==v['a'] and all(type(row) is list and len(row)==3 for row in s['rounds']) and type(s['final']) is list and len(s['final'])==2,'ProofShape')
    need(all(type(x) is tuple and len(x)==d and all(type(y) is int and 0<=y<r.sc.P for y in x) for row in s['rounds']+[s['final']] for x in row),'NoncanonicalField')
    t,point=transcript(v,expected,[proof['roots'][name] for name in NAMES],[child['state'] for child in children],d);instance,tables=part(p,proof,point,d)
    try:receipt=r.sc.verify_public(t,instance,s,tables)
    except ValueError as error:raise ValueError('BlockSum:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=[receipt['sc']],claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),channel_identity_numerator=v['ac'],sum_reduction_numerator=receipt['sc']['numerator'],denominator=r.sc.P**d))
