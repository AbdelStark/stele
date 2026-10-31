"""Draft RFC-0004 A3/A6 / RFC-0009 A2: canonical accumulated block signs.

Complete ranges precede faithful whole-integer lifts. All seven original
views remain consumed, including both occurrences of magnitude and sign.
"""
from dataclasses import dataclass
import struct
import attention_block_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-block-total-sign/v1\0'
NAMES=('offset','magnitude','sign','predecessor')


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    blocks: tuple
    identity: int
    offset: int
    magnitude: int
    sign: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.blocks) is tuple and 1<=len(p.blocks)<=constants['block_count_max'] and all(type(x) is int and 0<=x<=constants['block_id_max'] for x in p.blocks) and all(x<y for x,y in zip(p.blocks,p.blocks[1:])),'Spec')
    a=(p.schema.width-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=(p.offset,p.magnitude,p.sign)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==len(ids),'Spec')
    G=constants['total_max'];need(2*max(4*G,G+1)<r.sc.P,'FieldBound');caps=[(cap,)*p.schema.width for cap in (2*G,G,1,G)]
    ranges={name:r.Spec(256*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(zip(NAMES,caps),1)}
    for name,limit in zip(NAMES,(8,8,1,8)):need(r.derive(ranges[name],d)[3]<=limit,'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQII',1,d,p.repetitions,p.identity,len(p.blocks),len(encoded))+encoded
    raw+=b''.join(struct.pack('<I',block) for block in p.blocks)+b''.join(struct.pack('<Q',identity) for identity in ids)
    return dict(constants=constants,G=G,ranges=ranges,a=a,n=n,base=base,raw=raw)


def witness(p,offsets):
    v=derive(p,4);need(type(offsets) is list and len(offsets)==p.schema.width and all(type(x) is int and 0<=x<=2*v['G'] for x in offsets),'Input')
    magnitudes=[abs(x-v['G']) for x in offsets];signs=[int(x<v['G']) for x in offsets]
    return dict(offset=offsets.copy(),magnitude=magnitudes,sign=signs,predecessor=[m-b for m,b in zip(magnitudes,signs)])


def full(v,name,words,width):
    _,_,n,compact,_,_=r.derive(v['ranges'][name],4);r.vector(words,n*compact);need(compact<=width,'Capacity');return words+[0]*(n*(width-compact))


def roots(p,proof):
    v=derive(p,4);return [r.root(identity,full(v,name,proof[name]['words'],width)) for identity,name,width in ((p.offset,'offset',8),(p.magnitude,'magnitude',8),(p.sign,'sign',1))]


def expected_roots(p,offsets):
    v=derive(p,4);w=witness(p,offsets)
    def planes(xs,width):return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(v['n']-len(xs))]
    return [r.root(identity,planes(w[name],width)) for identity,name,width in ((p.offset,'offset',8),(p.magnitude,'magnitude',8),(p.sign,'sign',1))]


def parts(p,proof,d):
    v=derive(p,d);n,base=v['n'],v['base'];rows={}
    # The verifier calls this only after all four complete ranges. Static
    # nonnegative sides <=max(4G,G+1)<p/2 make both whole equalities faithful.
    for name in NAMES:
        words=full(v,name,proof[name]['words'],8);rows[name]=[sum(words[k*n+i]<<(8*k) for k in range(8)) for i in range(n)]
    def item(name,index,ids,terms,tables):
        return name,dict(id=1024*p.identity+128+index,m=v['a'],k=0,ids=ids,terms=[(r.sc.scalar(value,d),factors) for value,factors in terms]),[[r.sc.scalar(x,d) for x in row] for row in tables]
    return [item('SignRelation',0,[base+16,base+17,base+18,base+19],[(1,[0]),(2,[1,2]),(-1,[3]),(-1,[2])],[rows['offset'],rows['sign'],rows['magnitude'],[v['G'] if i<p.schema.width else 0 for i in range(n)]]),
            item('CanonicalZero',1,[base+18,base+20,base+17],[(1,[0]),(-1,[1]),(-1,[2])],[rows['magnitude'],rows['predecessor'],rows['sign']])]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==7 and type(states) is list and len(states)==4 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,offsets,d):
    v=derive(p,d);w=witness(p,offsets);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; the verifier independently checks every child and original."""
    v=derive(p,d);proof={name:pairs[name][0] for name in NAMES};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in NAMES],[pairs[name][1] for name in NAMES],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,offsets,d):
    return assemble(p,prepare(p,offsets,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(NAMES) and type(proof['zero']) is list and len(proof['zero'])==2,'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for name,actual,target in zip(('Offset','Magnitude','Sign'),roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    t=transcript(v,expected+[proof['roots'][name] for name in NAMES],[child['state'] for child in children],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==len(i['ids']) and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
