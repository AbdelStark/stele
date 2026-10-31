"""Draft RFC-0004 A3/A8: canonical residual numerator magnitude and sign.

O(N) byte/carry views and three batched A3s plus complete range/hash consumers.
Canonical zero uses a bounded byte sum; no wide integer is embedded in M31.
"""
from dataclasses import dataclass
import struct
import residual_bounds as residual
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/residual-sign/v1\0'
NAMES=('offset','magnitude','sign','predecessor','carry_0','carry_1')


@dataclass(frozen=True)
class Spec:
    schema: residual.Spec
    identity: int
    offset: int
    magnitude: int
    sign: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=residual.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.dimension;need(count<=16384,'Capacity');a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=(p.offset,p.magnitude,p.sign)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==3,'Spec')
    caps=[(constants['offset_max'],)*count,(constants['numerator_max'],)*count,(1,)*count,(2040,)*count]+[((4,)*count+(0,)*(n-count))*4]*2
    ranges={name:r.Spec(256*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(zip(NAMES,caps),1)}
    widths={name:r.derive(child,d)[3] for name,child in ranges.items()}
    need(widths['offset']<=8 and widths['magnitude']<=8 and widths['sign']==1 and widths['predecessor']==2 and widths['carry_0']==widths['carry_1']==1,'Capacity')
    need(2*max(1534,2041)<r.sc.P,'FieldBound');s=p.schema
    raw=PREFIX+struct.pack('<BBBQQQQIBBB',1,d,p.repetitions,p.identity,*ids,count,s.left_fraction,s.right_fraction,s.output_fraction)
    return dict(constants=constants,ranges=ranges,widths=widths,a=a,n=n,base=base,raw=raw)


def witness(p,offsets):
    v=derive(p,4);count=p.schema.dimension;n=v['n'];H=v['constants']['numerator_max']
    need(type(offsets) is list and len(offsets)==count and all(type(x) is int and 0<=x<=v['constants']['offset_max'] for x in offsets),'Input')
    ms=[abs(x-H) for x in offsets];ss=[int(x<H) for x in offsets];O=offsets+[0]*(n-count);M=ms+[0]*(n-count);S=ss+[0]*(n-count);carry=[0]*n;cs=[]
    for k in range(8):
        carry=[((O[i]>>(8*k)&255)+(2*S[i]-1)*(M[i]>>(8*k)&255)-(H>>(8*k)&255)+carry[i])//256 if i<count else 0 for i in range(n)]
        cs.extend(carry[i]+2 if i<count else 0 for i in range(n))
    return dict(offset=offsets.copy(),magnitude=ms,sign=ss,predecessor=[sum(m>>(8*k)&255 for k in range(8))-s for m,s in zip(ms,ss)],carry_0=cs[:4*n],carry_1=cs[4*n:])


def full_words(v,proof,name):
    words=proof[name]['words'];r.vector(words,v['widths'][name]*v['n']);return words+[0]*((8-v['widths'][name])*v['n'])


def roots(p,proof):
    v=derive(p,4);r.vector(proof['sign']['words'],v['n'])
    return [r.root(identity,full_words(v,proof,name)) for identity,name in ((p.offset,'offset'),(p.magnitude,'magnitude'))]+[r.root(p.sign,proof['sign']['words'])]


def expected_roots(p,offsets,magnitudes,signs):
    v=derive(p,4);count=p.schema.dimension
    need(all(type(row) is list and len(row)==count and all(type(x) is int and 0<=x<1<<64 for x in row) for row in (offsets,magnitudes)) and type(signs) is list and len(signs)==count and all(type(x) is int and x in (0,1) for x in signs),'Input')
    def planes(values):return [x>>(8*k)&255 for k in range(8) for x in values+[0]*(v['n']-count)]
    return [r.root(p.offset,planes(offsets)),r.root(p.magnitude,planes(magnitudes)),r.root(p.sign,signs+[0]*(v['n']-count))]


def parts(p,proof,d):
    v=derive(p,d);n,base=v['n'],v['base'];count=p.schema.dimension;H=v['constants']['numerator_max'];O=full_words(v,proof,'offset');M=full_words(v,proof,'magnitude');S=proof['sign']['words'];G=proof['predecessor']['words']
    r.vector(S,n);r.vector(G,2*n);carry=[]
    for name in ('carry_0','carry_1'):r.vector(proof[name]['words'],4*n);carry.extend(proof[name]['words'])
    endpoint=[2 if i<count else 0 for i in range(n)];mask510=[510 if i<count else 0 for i in range(n)]*8
    publicH=[(H>>(8*k)&255) if i<count else 0 for k in range(8) for i in range(n)]
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=1024*p.identity+128+index,m=m,k=0,ids=ids,terms=[(r.sc.scalar(value,d),factors) for value,factors in terms]),[[r.sc.scalar(x,d) for x in row] for row in rows]
    # Offsetting signed carries gives the +510 term. Exact endpoints and
    # static byte bounds make the column equality faithful over the integers.
    return [item('TerminalCarry',0,v['a'],[base+23,base+24],[(1,[0]),(-1,[1])],[carry[7*n:],endpoint]),
            item('SignColumns',1,v['a']+3,list(range(base+16,base+23)),[(1,[0]),(2,[1,2]),(1,[3]),(1,[4]),(-1,[5]),(-1,[2]),(-256,[6])],[O,S*8,M,endpoint+carry[:-n],mask510,publicH,carry]),
            # Sum of actual ranged magnitude bytes is <=2040<p/2; it is
            # zero exactly when the wide magnitude is zero, with no p alias.
            item('CanonicalZero',2,v['a'],[base+25,base+26,p.sign],[(1,[0]),(-1,[1]),(-1,[2])],[[sum(M[k*n+i] for k in range(8)) for i in range(n)],[G[i]+256*G[n+i] for i in range(n)],S])]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==9 and type(states) is list and len(states)==6 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,offsets,d):
    v=derive(p,d);w=witness(p,offsets);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; supplied states and coherent false columns grant no acceptance."""
    v=derive(p,d);proof={name:pairs[name][0] for name in NAMES};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in NAMES],[pairs[name][1] for name in NAMES],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,offsets,d):
    return assemble(p,prepare(p,offsets,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(NAMES) and type(proof['zero']) is list and len(proof['zero'])==3,'ProofShape')
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
    accounts=[child['account'] for child in children];account=dict(identities=[(item['identity_numerator'],item['identity_power']) for item in accounts],lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in accounts),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in accounts)+sum(row['numerator'] for row in records),denominator=r.sc.P**d)
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),account=account)
