"""Q26/Q31 static codes: RFC-0004 §5.5 / Draft A3/A8, revealing research.

O(NP) witness, views and folded A3 producer; inherited verifiers are reference.
"""
from dataclasses import dataclass
import struct
import row_bounds as row
import signed_source as ss

r=ss.r
need=r.need
RANGES=('quotient','remainder','carry')
NAMES=('input','output')+RANGES
AUX=('input_magnitude','output_magnitude','remainder','carry')
PREFIX=b'stele/research/q26/static-row-code/v1\0'
# Draft RFC-0004 A3/A8: the largest column side is 2*Magbyte+Sbyte+256*T.
COLUMN_BOUND=2*255+255+256*258


@dataclass(frozen=True)
class Spec:
    schema: row.Spec
    identity: int
    source: int
    scale: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=row.constants(p.schema); need(p.schema.mode=='static','Spec')
    base=(1<<63)+(1<<18)*p.identity; external=(p.source,p.scale,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    count=p.schema.dimension; a=(count-1).bit_length(); n=1<<a; bits=32 if p.schema.kind=='gated' else 16
    width=bits//8; b=width.bit_length()-1; remcap=2*p.schema.scale-1
    br=(max(1,(remcap.bit_length()+7)//8)-1).bit_length(); c=max(b,br); planes=1<<c
    need(n*planes<=4096,'Capacity')
    # Static domain follows integer division and actual Q/R caps, never observed magnitudes.
    need(min(1<<(bits-1),(255*p.schema.scale-1)//2)<=cert['source_max'] and 2*COLUMN_BOUND<r.sc.P,'FieldBound')
    source=ss.Spec(512*p.identity+1,p.source,base+1,bits,count,p.repetitions)
    output=ss.Spec(512*p.identity+2,p.output,base+2,8,count,p.repetitions)
    for child in (source,output): ss.derive(child,d)
    caps=((127,)*count,(remcap,)*count,(258,)*(n*planes))
    ranges={name:r.Spec(4096*p.identity+65+j,base+2+j,cap,p.repetitions) for j,(name,cap) in enumerate(zip(RANGES,caps))}
    for child in ranges.values(): r.derive(child,d)
    raw=PREFIX+struct.pack('<BBBQQQQBIBH',1,d,p.repetitions,p.identity,p.source,p.scale,p.output,int(bits==32),count,p.schema.fraction,p.schema.scale)
    return dict(input=source,output=output,**ranges,a=a,b=b,br=br,c=c,n=n,width=width,planes=planes,base=base,cert=cert,raw=raw)


def carry_words(p,xs,quotient,remainder):
    """Prover-only difference carries; supplied false relations confer no acceptance."""
    v=derive(p,4); count=p.schema.dimension; n=v['n']; r.vector(quotient,count); r.vector(remainder,count)
    need(type(xs) is list and len(xs)==count and all(type(x) is int for x in xs),'Input')
    mags=[abs(x) for x in xs]+[0]*(n-count); qs=quotient+[0]*(n-count); rs=remainder+[0]*(n-count); incoming=[0]*n; carry=[]
    for j in range(v['planes']):
        next_c=[]
        for i in range(n):
            sb=p.schema.scale>>(8*j)&255 if i<count else 0
            numerator=2*sb*qs[i]+(rs[i]>>(8*j)&255)+incoming[i]-2*(mags[i]>>(8*j)&255)-sb
            need(numerator%256==0,'Witness'); next_c.append(numerator//256)
        incoming=next_c; carry.extend(x+3 for x in incoming)
    return carry


def witness(p,xs):
    derive(p,4); need(type(xs) is list,'Input'); row.inputs(p.schema,tuple(xs)); scale=p.schema.scale
    pairs=[divmod(2*abs(x)+scale,2*scale) for x in xs]; q=[x[0] for x in pairs]; rem=[x[1] for x in pairs]
    need(all(x<=127 for x in q),'OutputRange')
    return dict(codes=[-value if x<0 else value for x,value in zip(xs,q)],quotient=q,remainder=rem,carry=carry_words(p,xs,q,rem))


def scale_root(p):
    v=derive(p,4)
    return r.root(p.scale,list(p.schema.scale.to_bytes(v['width'],'little')))


def scale_bytes(p,v):
    return [p.schema.scale>>(8*j)&255 if i<p.schema.dimension else 0 for j in range(v['planes']) for i in range(v['n'])]


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(ss.derive(v['input'],4)['ranges'][0],proof['input']['ranges'][0]['words']),scale_root(p),
            r.source_root(ss.derive(v['output'],4)['ranges'][0],proof['output']['ranges'][0]['words'])]


def bound(expected,proof):
    return expected+[proof['roots'][name] for name in AUX]


def parts(p,proof,d):
    v=derive(p,d); n,width,planes,base=v['n'],v['width'],v['planes'],v['base']; remwidth=1<<v['br']
    source=proof['input']['ranges']; mag=source[1]['words']; sin=source[2]['words']; sout=proof['output']['ranges'][2]['words']
    q=proof['quotient']['words']; rem=proof['remainder']['words']; tw=proof['carry']['words']; size=n*planes
    for xs,count in ((mag,n*width),(sin,2*n),(sout,2*n),(q,n),(rem,n*remwidth),(tw,2*size)): r.vector(xs,count)
    # Actual carry range proves these two byte planes before this linear packing.
    carry=[tw[i]+256*tw[size+i] for i in range(size)]
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=16384*p.identity+512+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(x,d),factors) for x,factors in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in rows]
    return [item('RoundedDivision',0,v['a']+v['c'],list(range(base+16,base+22)),
                 [(2,[0,1]),(1,[2]),(-2,[3]),(-1,[0]),(1,[4]),(-256,[5]),(765,[])],
                 [scale_bytes(p,v),q*planes,rem+[0]*(n*(planes-remwidth)),mag+[0]*(n*(planes-width)),[3]*n+carry[:-n],carry]),
            item('TerminalCarry',1,v['a'],[base+22],[(1,[0]),(-3,[])],[carry[-n:]]),
            item('SignTransfer',2,v['a'],[base+23,base+24,base+2],[(1,[0,2]),(-1,[1,2])],[sin[:n],sout[:n],q])]


def transcript(p,bounds,states,d):
    need(type(bounds) is list and len(bounds)==7 and type(states) is list and len(states)==5 and
         all(type(x) is bytes and len(x)==32 for x in bounds+states),'Root')
    return r.scalar.Transcript(derive(p,d)['raw']+b''.join(bounds+states),d)


def prepare(p,xs,d):
    v=derive(p,d); w=witness(p,xs)
    return dict(input=ss.prove(v['input'],xs,d),output=ss.prove(v['output'],w['codes'],d),
                **{name:r.prove(v[name],w[name],d) for name in RANGES})


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; only verify authorizes a statement."""
    v=derive(p,d); proof={name:pairs[name][0] for name in NAMES}
    proof['roots']=dict(input_magnitude=r.root(v['base']+1,proof['input']['ranges'][1]['words']),
        output_magnitude=r.root(v['base']+2,proof['output']['ranges'][1]['words']),
        **{name:r.source_root(v[name],proof[name]['words']) for name in RANGES[1:]})
    t=transcript(p,bound(roots(p,proof),proof),[pairs[name][1] for name in NAMES],d)
    proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,xs,d):
    return assemble(p,prepare(p,xs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(AUX),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root')
    need(type(proof['zero']) is list and len(proof['zero'])==3,'ProofShape'); need(expected[1]==scale_root(p),'Scale:CommitmentMismatch'); children=[]
    targets=[[expected[0],proof['roots']['input_magnitude']],[expected[2],proof['roots']['output_magnitude']],
             proof['roots']['output_magnitude'],proof['roots']['remainder'],proof['roots']['carry']]
    for name,target,verifier in zip(NAMES,targets,(ss.verify,ss.verify,r.verify,r.verify,r.verify)):
        try: children.append(verifier(v[name],target,proof[name],d))
        except ValueError as error: raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(p,bound(expected,proof),[child['state'] for child in children],d); records=[]; claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
             all(type(xs) is list and len(xs)==r.sc.degree(i)+1 for xs in part['rounds']) and
             type(part['final']) is list and len(part['final'])==len(i['ids']) and
             all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
        try: receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),
                account=dict(identities=accounts[0]['identities']+accounts[1]['identities']+
                    [(x['identity_numerator'],x['identity_power']) for x in accounts[2:]],
                    lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
