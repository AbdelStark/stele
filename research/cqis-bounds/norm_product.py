"""RFC-0022 §2.3 product / Draft RFC-0004 A3: consumed revealing research.

O(N) byte views and one folded A3, with five complete range consumers.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import function_identity as fn

need=r.need
NAMES=('xy','offset','output','carry_wide','carry_byte')
AUX=('offset','carry_wide','carry_byte')
PREFIX=b'stele/research/q26/norm-product/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    xy: int
    reciprocal: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.d;a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<18)*p.identity;external=(p.xy,p.reciprocal,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    cert=norm.limbs.derive(norm.column_specs(p.schema)['product'])
    need(cert['carry_caps']==(0,254,318,318,128,16,0) and max(cert['lhs']+cert['rhs'])==81663 and 2*81663<r.sc.P,'FieldBound')
    carry_caps=lambda caps:tuple(cap if i<count else 0 for cap in caps for i in range(n))
    sources=(p.xy,base+1,p.output,base+2,base+3)
    caps=((1<<30,)*count,(8192,),(1<<44,)*count,carry_caps(cert['carry_caps'][1:4]),carry_caps(cert['carry_caps'][4:6]))
    children={name:r.Spec(4096*p.identity+j+1,source,bounds,p.repetitions) for j,(name,source,bounds) in enumerate(zip(NAMES,sources,caps))}
    for child in children.values():r.derive(child,d)
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQ',1,d,p.repetitions,p.identity,*external)+fn.encode(function)
    return dict(**children,a=a,n=n,base=base,cert=cert,raw=raw)


def witness(p,xs,j):
    v=derive(p,4);need(type(xs) is list and len(xs)==p.schema.d and all(type(x) is int and 0<=x<=1<<30 for x in xs) and type(j) is int and 8192<=j<=16384,'Input')
    n=v['n'];padded=xs+[0]*(n-len(xs));incoming=[0]*n;carry=[]
    for column in range(6):
        incoming=[(incoming[i]+sum((x>>(8*k)&255)*(j>>(8*(column-k))&255) for k in range(4) if 0<=column-k<2))//256 for i,x in enumerate(padded)]
        carry.extend(incoming)
    return dict(xy=xs,offset=[j-8192],output=[x*j for x in xs],carry_wide=carry[:3*n],carry_byte=carry[3*n:5*n])


def reciprocal(words):
    r.vector(words,2);value=8192+words[0]+256*words[1];r.vector([value],1)
    return value


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(v['xy'],proof['xy']['words']),r.root(p.reciprocal,[reciprocal(proof['offset']['words'])]),r.source_root(v['output'],proof['output']['words'])]


def expected_roots(p,xs,j,output):
    v=derive(p,4);witness(p,xs,j)
    need(type(output) is list and len(output)==p.schema.d and all(type(x) is int and 0<=x<1<<64 for x in output),'Output')
    padded=output+[0]*(v['n']-len(output));words=[x>>(8*k)&255 for k in range(8) for x in padded]
    return [r.source_root(v['xy'],r.witness(v['xy'],xs)[0]),r.root(p.reciprocal,[j]),r.source_root(v['output'],words)]


def parts(p,proof,d):
    v=derive(p,d);n,base=v['n'],v['base'];xs=proof['xy']['words'];offset=proof['offset']['words'];output=proof['output']['words'];wide=proof['carry_wide']['words'];small=proof['carry_byte']['words']
    for values,size in ((xs,4*n),(offset,2),(output,8*n),(wide,8*n),(small,2*n)):r.vector(values,size)
    # RFC-0022 product: C1..C3 are two-byte words; C4..C5 are bytes.
    # The range proof consumes the fourth padded wide-carry plane as zero.
    carry=[wide[i]+256*wide[4*n+i] for i in range(3*n)]+small+[0]*(3*n)
    # Convolution with J0 and J1. C0 and C6..C8 are fixed public zero;
    # the two high output planes remain in the actual column relation.
    zero=[0]*n;rows=[xs+zero*4,[offset[0]]*(8*n),zero+xs+zero*3,[offset[1]+32]*(8*n),zero+carry[:-n],output,carry]
    i=dict(id=16384*p.identity+512,m=v['a']+3,k=0,ids=list(range(base+16,base+21))+[p.output,base+21],
        terms=[(r.sc.scalar(x,d),factors) for x,factors in ((1,[0,1]),(1,[2,3]),(1,[4]),(-1,[5]),(-256,[6]))])
    return i,[[r.sc.scalar(x,d) for x in values] for values in rows]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==6 and type(states) is list and len(states)==5 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,j,d):
    v=derive(p,d);w=witness(p,xs,j)
    return {name:r.prove(v[name],w[name],d) for name in NAMES}


def assemble(p,pairs,d):
    """Producer only: every source, range and column remains mandatory in verify."""
    v=derive(p,d);proof={name:pairs[name][0] for name in NAMES};proof['roots']={name:r.source_root(v[name],proof[name]['words']) for name in AUX}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in AUX],[pairs[name][1] for name in NAMES],d)
    proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,xs,j,d):
    return assemble(p,prepare(p,xs,j,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(AUX),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    targets=(expected[0],proof['roots']['offset'],expected[2],proof['roots']['carry_wide'],proof['roots']['carry_byte'])
    for name,target in zip(NAMES,targets):
        try:children.append(r.verify(v[name],target,proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
        if name=='offset':
            # Actual verified bounded bytes determine J exactly. The root has
            # the same single canonical-u32 leaf as the complete rsqrt consumer.
            need(r.root(p.reciprocal,[reciprocal(proof[name]['words'])])==expected[1],'Reciprocal:CommitmentMismatch')
    i,tables=parts(p,proof,d);part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m']
        and all(type(xs) is list and len(xs)==3 for xs in part['rounds']) and type(part['final']) is list and len(part['final'])==7 and all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
    t=transcript(v,expected+[proof['roots'][name] for name in AUX],[child['state'] for child in children],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('ProductColumns:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),
        account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],
            lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in receipt['sc']),denominator=r.sc.P**d))
