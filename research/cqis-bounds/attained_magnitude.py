"""Q26/Q31 attained magnitudes: RFC-0004 §5.5 / Draft A3/A8, revealing research.

O(NB) byte arithmetic and original consumption, plus complete nested range work.
"""
from dataclasses import dataclass
import struct
import row_bounds as row
import signed_source as ss

r=ss.r
need=r.need
NAMES=('input','maximum','gap','indicator')
PREFIX=b'stele/research/q26/attained-magnitude/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: row.Spec
    identity: int
    source: int
    maximum: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(p.schema) is row.Spec and type(d) is int and d in (4,8),'Spec')
    cert=row.derive(p.schema); need(p.schema.mode=='dynamic','Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<46 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.dimension; need(count<=2048,'Capacity')
    a=(count-1).bit_length(); n=1<<a; bits=16 if p.schema.kind=='wide' else 32; width=bits//8; b=width.bit_length()-1
    base=(1<<63)+65536*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+65536 for x in (p.source,p.maximum)) and p.source!=p.maximum,'Spec')
    inp=ss.Spec(128*p.identity+1,p.source,base+1,bits,count,p.repetitions)
    ranges={name:r.Spec(1024*p.identity+32+j,source,caps,p.repetitions) for j,(name,source,caps) in enumerate(
        (('maximum',p.maximum,(cert['source_max'],)),('gap',base+2,(cert['source_max'],)*count),('indicator',base+3,(1,)*count)))}
    ss.derive(inp,d)
    for child in ranges.values(): r.derive(child,d)
    # Byte sides <=511 and bit sum <=N lift to integers; no whole gated sum in M31.
    need(2*511<r.sc.P and 2*n<r.sc.P,'FieldBound')
    raw=PREFIX+struct.pack('<BBBQQQBIB',1,d,p.repetitions,p.identity,p.source,p.maximum,int(p.schema.kind=='gated'),count,p.schema.fraction)
    return dict(input=inp,**ranges,a=a,b=b,n=n,width=width,base=base,cert=cert,raw=raw)


def witness(p,xs):
    v=derive(p,4); count=p.schema.dimension; n,width=v['n'],v['width']; c=v['cert']
    need(type(xs) is list and len(xs)==count and all(type(x) is int and -c['source_max']<=x<=c['source_high'] for x in xs),'Input')
    mags=[abs(x) for x in xs]; maximum=max(mags); gaps=[maximum-x for x in mags]
    selected=mags.index(maximum); indicator=[int(i==selected) for i in range(count)]
    mags+=[0]*(n-count); gs=gaps+[0]*(n-count); cs=[]; incoming=[0]*n
    for j in range(width):
        incoming=[((mags[i]>>(8*j)&255)+(gs[i]>>(8*j)&255)+incoming[i])//256 for i in range(n)]; cs.extend(incoming)
    return [maximum],gaps,indicator,cs


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(ss.derive(v['input'],4)['ranges'][0],proof['input']['ranges'][0]['words']),
            r.source_root(v['maximum'],proof['maximum']['words'])]


def parts(p,proof,d):
    v=derive(p,d); n,width,base=v['n'],v['width'],v['base']; count=n*width
    mag=proof['input']['ranges'][1]['words']; maximum=proof['maximum']['words']
    gap=proof['gap']['words']; indicator=proof['indicator']['words']; cs=proof['carry']
    for xs,size in ((mag,count),(maximum,width),(gap,count),(indicator,n),(cs,count)): r.vector(xs,size)
    masked=[maximum[j] if i<p.schema.dimension else 0 for j in range(width) for i in range(n)]
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=4096*p.identity+256+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(c,d),factors) for c,factors in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in rows]
    return [item('MagnitudeGap',0,v['a']+v['b'],[base+1,base+2,base+8,base+9,base+4],
                 [(1,[0]),(1,[1]),(1,[2]),(-1,[3]),(-256,[4])],[mag,gap,[0]*n+cs[:count-n],masked,cs]),
            item('CarryBoolean',1,v['a']+v['b'],[base+4],[(1,[0,0]),(-1,[0])],[cs]),
            item('TerminalCarry',2,v['a'],[base+10],[(1,[0])],[cs[count-n:]]),
            item('Attainment',3,v['a']+v['b'],[base+11,base+2],[(1,[0,1])],[indicator*width,gap])]


def one_descriptor(p,v,d):
    return dict(id=4096*p.identity+260,m=v['a'],ids=[v['base']+3],terms=[(r.sc.scalar(1,d),[0])],sum=r.sc.scalar(1,d))


def transcript(p,bound,states,d):
    need(type(bound) is list and len(bound)==6 and type(states) is list and len(states)==4 and
         all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(derive(p,d)['raw']+b''.join(bound+states),d)


def prepare(p,xs,d):
    v=derive(p,d); maximum,gaps,indicator,cs=witness(p,xs)
    return dict(input=ss.prove(v['input'],xs,d),**{name:r.prove(v[name],values,d) for name,values in
                zip(NAMES[1:],(maximum,gaps,indicator))}),cs


def assemble(p,pairs,cs,d):
    """Arithmetic producer for supplied child proofs; full acceptance is verify."""
    v=derive(p,d); r.vector(cs,v['n']*v['width']); proof={name:pairs[name][0] for name in NAMES}
    proof.update(mag_root=r.root(v['base']+1,proof['input']['ranges'][1]['words']),
                 gap_root=r.source_root(v['gap'],proof['gap']['words']),indicator_root=r.source_root(v['indicator'],proof['indicator']['words']),
                 carry_root=r.root(v['base']+4,cs),carry=list(cs))
    expected=roots(p,proof); bound=[expected[0],proof['mag_root'],expected[1],proof['gap_root'],proof['indicator_root'],proof['carry_root']]
    t=transcript(p,bound,[pairs[name][1] for name in NAMES],d)
    proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    proof['one'],_=r.sc.prove(t,one_descriptor(p,v,d),[[r.sc.scalar(x,d) for x in proof['indicator']['words']]])
    return proof,t.state


def prove(p,xs,d):
    return assemble(p,*prepare(p,xs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'mag_root','gap_root','indicator_root','carry_root','carry','zero','one'},'ProofShape')
    need(all(type(proof[k]) is bytes and len(proof[k])==32 for k in ('mag_root','gap_root','indicator_root','carry_root')),'Root')
    need(type(proof['zero']) is list and len(proof['zero'])==4,'ProofShape')
    r.vector(proof['carry'],v['n']*v['width']); need(r.root(v['base']+4,proof['carry'])==proof['carry_root'],'Carry:CommitmentMismatch')
    bound=[expected[0],proof['mag_root'],expected[1],proof['gap_root'],proof['indicator_root'],proof['carry_root']]; children=[]
    for name,root,verifier in zip(NAMES,([expected[0],proof['mag_root']],expected[1],proof['gap_root'],proof['indicator_root']),(ss.verify,r.verify,r.verify,r.verify)):
        try: children.append(verifier(v[name],root,proof[name],d))
        except ValueError as error: raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(p,bound,[child['state'] for child in children],d); records=[]; claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
             all(type(xs) is list and len(xs)==r.sc.degree(i)+1 for xs in part['rounds']) and
             type(part['final']) is list and len(part['final'])==len(i['ids']) and
             all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
        try: receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    part=proof['one']
    need(type(part) is dict and set(part)=={'rounds','final'} and type(part['rounds']) is list and len(part['rounds'])==v['a'] and
         all(type(xs) is list and len(xs)==2 for xs in part['rounds']) and type(part['final']) is list and len(part['final'])==1,'ProofShape')
    try:
        r.lu.ft.fields(sum(part['rounds'],[])+part['final'],d)
        one=r.sc.verify_reduction(t,one_descriptor(p,v,d),part)
        need(r.zc.folded([r.sc.scalar(x,d) for x in proof['indicator']['words']],one['point'])==one['claims'][0][1],'ClaimMismatch')
    except ValueError as error: raise ValueError('OneHot:'+str(error)) from None
    accounts=[child['account'] for child in children]; signed=accounts[0]
    return dict(state=t.state,children=children,sc=records,claims=claims,one=one,draws=dict(t.draws),
                account=dict(identities=signed['identities']+[(x['identity_numerator'],x['identity_power']) for x in accounts[1:]],
                    lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),
                    selection_reduction_numerator=one['sc']['numerator'],denominator=r.sc.P**d))
