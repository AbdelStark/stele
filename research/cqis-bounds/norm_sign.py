"""RFC-0022 §2.3 canonical product sign / Draft RFC-0004 A3 research.

O(N) predicates/sign views and A3 producers, with complete xy/range consumers.
"""
from dataclasses import dataclass
import struct
import norm_xy as xy
import function_identity as fn

norm=xy.norm
r=xy.r
need=r.need
NAMES=('flags','predecessor')
PREFIX=b'stele/research/q26/norm-sign/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    left: int
    right: int
    product: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');cert=norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<42 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.d;a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<20)*p.identity;external=(p.left,p.right,p.product,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<20) for x in external) and len(set(external))==4,'Spec')
    need(2*max(cert['sign_lhs'],cert['sign_rhs'])<r.sc.P,'FieldBound')
    child=xy.Spec(p.schema,4*p.identity+1,p.left,p.right,p.product,p.repetitions);xy.derive(child,d)
    flags=r.Spec(16384*p.identity+1,base+1,((1,)*count+(0,)*(n-count))*3,p.repetitions)
    predecessor=r.Spec(16384*p.identity+2,base+2,((32767,)*count+(0,)*(n-count))*2,p.repetitions)
    for item in (flags,predecessor):r.derive(item,d)
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQQ',1,d,p.repetitions,p.identity,*external)+fn.encode(function)
    return dict(xy=child,flags=flags,predecessor=predecessor,a=a,n=n,base=base,cert=cert,raw=raw)


def witness(p,xs,ys):
    v=derive(p,4);need(type(xs) is list and type(ys) is list,'Input');norm.inputs(p.schema,tuple(xs),tuple(ys));n=v['n']
    left=xs+[0]*(n-len(xs));right=ys+[0]*(n-len(ys));nx=[int(x!=0) for x in left];ny=[int(y!=0) for y in right]
    signs=[int(bool(x and y) and (x<0)!=(y<0)) for x,y in zip(left,right)]
    return dict(flags=nx+ny+signs,predecessor=[max(abs(x)-1,0) for x in left+right])


def sign_root(p,words):
    v=derive(p,4);n=v['n'];r.vector(words,4*n)
    return r.root(p.output,words[2*n:3*n])


def roots(p,proof):
    v=derive(p,4)
    return xy.roots(v['xy'],proof['xy'])+[sign_root(p,proof['flags']['words'])]


def expected_roots(p,xs,ys,products,signs):
    v=derive(p,4);witness(p,xs,ys);r.vector(signs,p.schema.d)
    return xy.expected_roots(v['xy'],xs,ys,products)+[r.root(p.output,signs+[0]*(v['n']-len(signs)))]


def parts(p,proof,d):
    v=derive(p,d);n,base=v['n'],v['base'];mags=[proof['xy'][name]['ranges'][1]['words'] for name in ('left','right')];signs=[proof['xy'][name]['ranges'][2]['words'] for name in ('left','right')]
    flags=proof['flags']['words'];pred=proof['predecessor']['words']
    for values,size in zip(mags+signs+[flags,pred],(2*n,2*n,2*n,2*n,4*n,4*n)):r.vector(values,size)
    mag=[words[i]+256*words[n+i] for words in mags for i in range(n)];predecessor=[pred[i]+256*pred[2*n+i] for i in range(2*n)];nz=flags[:2*n];zero=[0]*(2*n)
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=65536*p.identity+512+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(c,d),factors) for c,factors in terms]),[[r.sc.scalar(x,d) for x in values] for values in rows]
    # RFC-0022 zero predicates: first half m=k+n, second half m*(1-n)=0.
    # Verified whole k<=32767 and Boolean n rule out n=1 at m=0.
    return [item('Predicates',0,v['a']+2,list(range(base+16,base+20)),[(1,[0]),(-1,[1]),(-1,[2]),(-1,[0,3])],
                 [mag+mag,predecessor+zero,nz+zero,zero+nz]),
            # Canonical signed sources already give sx=0 at mx=0 and sy=0
            # at my=0. This degree-two identity is XOR only when both are nonzero.
            item('Sign',1,v['a'],list(range(base+20,base+24))+[p.output],[(1,[0,3]),(1,[1,2]),(-2,[0,1]),(-1,[4])],
                 [signs[0][:n],signs[1][:n],flags[:n],flags[n:2*n],flags[2*n:3*n]])]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==6 and type(states) is list and len(states)==3 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,ys,d):
    v=derive(p,d);w=witness(p,xs,ys)
    return dict(xy=xy.prove(v['xy'],xs,ys,d),**{name:r.prove(v[name],w[name],d) for name in NAMES})


def assemble(p,pairs,d):
    """Producer only; the complete xy/range/original consumers remain mandatory."""
    v=derive(p,d);proof={name:pairs[name][0] for name in ('xy',)+NAMES};proof['roots']={name:r.source_root(v[name],proof[name]['words']) for name in NAMES}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in NAMES],[pairs[name][1] for name in ('xy',)+NAMES],d)
    proof['zero']=[r.zero_prove(t,i,rows) for _,i,rows in parts(p,proof,d)]
    return proof,t.state


def prove(p,xs,ys,d):
    return assemble(p,prepare(p,xs,ys,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==4 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'xy','roots','zero'}|set(NAMES) and type(proof['roots']) is dict and set(proof['roots'])==set(NAMES),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()) and type(proof['zero']) is list and len(proof['zero'])==2,'ProofShape')
    try:child=xy.verify(v['xy'],expected[:3],proof['xy'],d)
    except ValueError as error:raise ValueError('XY:'+str(error)) from None
    ranges=[]
    for name in NAMES:
        try:ranges.append(r.verify(v[name],proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    need(sign_root(p,proof['flags']['words'])==expected[3],'Sign:CommitmentMismatch')
    t=transcript(v,expected+[proof['roots'][name] for name in NAMES],[child['state']]+[part['state'] for part in ranges],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m']
            and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==len(i['ids']) and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    inherited=child['account'];accounts=[part['account'] for part in ranges]
    return dict(state=t.state,xy=child,ranges=ranges,sc=records,claims=claims,draws=dict(t.draws),
        account=dict(identities=inherited['identities']+[(x['identity_numerator'],x['identity_power']) for x in accounts],
            lookup_reduction_numerator=inherited['lookup_reduction_numerator']+sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=inherited['range_reduction_numerator']+sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
