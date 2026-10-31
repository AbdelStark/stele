"""RFC-0022 §2.3 configured output / revealing Draft RFC-0004 A3.

O(N) exact source joins; four complete children, no new algebraic challenge.
Full normalization must still bind N/a/A/D to X and J to configured rsqrt.
"""
from dataclasses import dataclass
import struct
import norm_output_factors as factors
import norm_signed_output as signed
import norm_product as product
import norm_left as left
import norm_division as division
import function_identity as fn

norm=signed.norm
r=signed.r
need=r.need
NAMES=('source','exponent','scaled','divisor','factors','left','right','xy','sign','output','magnitude','reciprocal','product','quotient_product','remainder')
PREFIX=b'stele/research/q26/norm-configured-output/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    exponent: int
    scaled: int
    divisor: int
    factors: int
    left: int
    right: int
    xy: int
    sign: int
    output: int
    magnitude: int
    reciprocal: int
    product: int
    quotient_product: int
    remainder: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<28 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<34)*p.identity;ids=tuple(getattr(p,name) for name in NAMES)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<34) for x in ids) and len(set(ids))==len(NAMES),'Spec')
    children=dict(factors=factors.Spec(p.schema,16*p.identity+1,*ids[:5],p.repetitions),signed=signed.Spec(p.schema,4096*p.identity+1,*ids[5:11],p.repetitions),product=product.Spec(p.schema,65536*p.identity+1,p.xy,p.reciprocal,p.product,p.repetitions),left=left.Spec(p.schema,65536*p.identity+2,p.product,base+3,p.magnitude,p.repetitions),division=division.Spec(p.schema,4096*p.identity+2,p.magnitude,base+1,p.quotient_product,p.product,base+2,base+4,p.remainder,p.repetitions))
    for name,module in (('factors',factors),('signed',signed),('product',product),('left',left),('division',division)):module.derive(children[name],d)
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBB'+'Q'*(1+len(NAMES)),1,d,p.repetitions,p.identity,*ids)+fn.encode(function)
    return dict(**children,base=base,n=1<<(s.d-1).bit_length(),raw=raw)


def witness(p,xs,hs,j,a):
    v=derive(p,4);need(type(xs) is list and type(hs) is list,'Input');norm.inputs(p.schema,tuple(xs),tuple(hs));fs=factors.words(p.schema,a)
    need(type(j) is int and 8192<=j<=16384,'Input');b,h,l=(int.from_bytes(bytes(fs[start:end]),'little') for start,end in ((2,18),(18,34),(34,42)))
    xy=[abs(x*y) for x,y in zip(xs,hs)];ts=[x*j for x in xy];qs=[t*l if fs[0] else (t+h)//b for t in ts];ys=[-q if x*y<0 else q for x,y,q in zip(xs,hs,qs)];signed.inputs(v['signed'],xs,hs,ys)
    return dict(xy=xy,t=ts,q=qs,y=ys,qd=[0]*len(xs) if fs[0] else [q*b for q in qs],remainder=[0]*len(xs) if fs[0] else [(t+h)%b for t in ts],b=b,h=h,l=l,branch='left' if fs[0] else 'division')


def expected_roots(p,n,a,xs,hs,j):
    v=derive(p,4);w=witness(p,xs,hs,j,a);cert=norm.constants(p.schema);fs=factors.words(p.schema,a)
    bound=factors.expected_roots(v['factors'],n,a,n<<(-2*min(a,0)),cert['P']<<(2*max(a,0)),fs)+signed.expected_roots(v['signed'],xs,hs,w['y'])
    bound+=product.expected_roots(v['product'],w['xy'],j,w['t'])[1:]
    return bound+[r.root(identity,[x>>(8*k)&255 for k in range(16) for x in values+[0]*(v['n']-len(values))]) for identity,values in ((p.quotient_product,w['qd']),(p.remainder,w['remainder']))]


def roots(p,proof):
    """Producer helper; acceptance obtains the branch only after full verification."""
    v=derive(p,4);bound=factors.roots(v['factors'],proof['factors'])+signed.roots(v['signed'],proof['signed'])+product.roots(v['product'],proof['product'])[1:]
    if proof['factors']['factors'][0]:return bound+[r.root(identity,[0]*(16*v['n'])) for identity in (p.quotient_product,p.remainder)]
    child=division.roots(v['division'],proof['division']);return bound+[child[2],child[6]]


def transcript(v,bound,branch,total,states,d):
    need(type(bound) is list and len(bound)==15 and branch in ('left','division') and type(total) is list and len(total)==int(branch=='division') and type(states) is list and len(states)==4 and all(type(x) is bytes and len(x)==32 for x in bound+total+states),'Root')
    return r.scalar.Transcript(v['raw']+bytes([int(branch=='division')])+b''.join(bound+total+states),d)


def prepare(p,n,a,xs,hs,j,d):
    v=derive(p,d);w=witness(p,xs,hs,j,a)
    pairs=dict(factors=factors.prove(v['factors'],n,a,d),signed=signed.prove(v['signed'],xs,hs,w['y'],d),product=product.prove(v['product'],w['xy'],j,d))
    pairs['round']=left.prove(v['left'],w['t'],w['l'],w['q'],d) if w['branch']=='left' else division.prove(v['division'],w['t'],w['h'],w['q'],w['b'],w['remainder'],d)
    return pairs


def assemble(p,pairs,d):
    """Producer only; every child and shared source still verify independently."""
    v=derive(p,d);proof={name:pairs[name][0] for name in ('factors','signed','product')};branch='left' if proof['factors']['factors'][0] else 'division';proof[branch]=pairs['round'][0];total=[]
    if branch=='division':proof['total_root']=division.roots(v['division'],proof[branch])[5];total=[proof['total_root']]
    return proof,transcript(v,roots(p,proof),branch,total,[pairs[name][1] for name in ('factors','signed','product','round')],d).state


def prove(p,n,a,xs,hs,j,d):
    return assemble(p,prepare(p,n,a,xs,hs,j,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==15 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and 'factors' in proof,'ProofShape')
    try:factor=factors.verify(v['factors'],expected[:5],proof['factors'],d)
    except ValueError as error:raise ValueError('Factors:'+str(error)) from None
    fs=proof['factors']['factors'];need(fs[:2] in ([1,0],[0,1]),'Branch');branch='left' if fs[0] else 'division'
    need(set(proof)=={'factors','signed','product',branch}|({'total_root'} if branch=='division' else set()),'ProofShape');total=[]
    if branch=='division':
        need(type(proof['total_root']) is bytes and len(proof['total_root'])==32,'Root');total=[proof['total_root']]
    children=[factor]
    for name,module,targets in (('signed',signed,expected[5:11]),('product',product,[expected[7],expected[11],expected[12]])):
        try:children.append(module.verify(v[name],targets,proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    if branch=='left':
        for index,identity,label in ((13,p.quotient_product,'UnusedQuotientProduct'),(14,p.remainder,'UnusedRemainder')):need(expected[index]==r.root(identity,[0]*(16*v['n'])),label+':CommitmentMismatch')
        module=left;targets=[expected[12],r.root(v['base']+3,fs[34:42]),expected[10]]
    else:
        module=division;targets=[expected[10],r.root(v['base']+1,fs[2:18]),expected[13],expected[12],r.root(v['base']+2,fs[18:34]),total[0],expected[14]]
    try:children.append(module.verify(v[branch],targets,proof[branch],d))
    except ValueError as error:raise ValueError(branch.title()+':'+str(error)) from None
    t=transcript(v,expected,branch,total,[child['state'] for child in children],d);accounts=[child['account'] for child in children];account=dict(accounts[0])
    account['identities']=sum((item['identities'] for item in accounts),[])
    for name in ('lookup_reduction_numerator','range_reduction_numerator'):account[name]=sum(item[name] for item in accounts)
    return dict(state=t.state,branch=branch,children=children,draws=dict(t.draws),account=account)
