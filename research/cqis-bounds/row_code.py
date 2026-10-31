"""Q26/Q31 dynamic row codes: RFC-0004 §5.5 / Draft A3/A8, revealing research.

O(NP) witness, view construction and folded A3 producer; inherited verifiers are reference.
"""
from dataclasses import dataclass
import struct
import dynamic_scale as ds

ss=ds.am.ss
r=ds.r
need=r.need
RANGES=('quotient','remainder','remainder_gap','zero_gap','nonzero','predecessor','carry')
NAMES=('scale','output')+RANGES
AUX=('magnitude',)+RANGES[1:]
PREFIX=b'stele/research/q26/row-code/v1\0'
# Draft RFC-0004 A3/A8: the largest column side is 2*Magbyte+Sbyte+256*T.
COLUMN_BOUND=2*255+255+256*258


@dataclass(frozen=True)
class Spec:
    schema: ds.am.row.Spec
    identity: int
    source: int
    scale: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<36 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<26)*p.identity; external=(p.source,p.scale,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<26) for x in external) and len(set(external))==3,'Spec')
    scale=ds.Spec(p.schema,16*p.identity+1,p.source,p.scale,p.repetitions); sv=ds.derive(scale,d); cert=sv['cert']
    count=p.schema.dimension; a=(count-1).bit_length(); n=1<<a; width=sv['width']; b=sv['b']; smax=cert['scale_max']
    digits=(max(2*cert['source_max']+smax,256*smax-1).bit_length()+7)//8; c=(digits-1).bit_length(); planes=1<<c
    need(n*planes<=65536,'Capacity')
    output=ss.Spec(131072*p.identity+32768,p.output,base+1,8,count,p.repetitions); ss.derive(output,d)
    caps=((127,)*count,(2*smax-1,)*count,(2*smax-1,)*count,(127,)*count,(1,),(smax-1,),(258,)*(n*planes))
    ranges={name:r.Spec(1048576*p.identity+524288+j,base+1+j,cap,p.repetitions) for j,(name,cap) in enumerate(zip(RANGES,caps))}
    for child in ranges.values(): r.derive(child,d)
    need(2*max(COLUMN_BOUND,4*smax-1,254,smax)<r.sc.P,'FieldBound')
    raw=PREFIX+struct.pack('<BBBQQQQBIB',1,d,p.repetitions,p.identity,p.source,p.scale,p.output,int(p.schema.kind=='gated'),count,p.schema.fraction)
    return dict(scale=scale,output=output,**ranges,a=a,b=b,c=c,n=n,width=width,planes=planes,base=base,cert=cert,raw=raw)


def carry_words(p,xs,scale,quotient,remainder):
    """Prover-only signed carry construction for supplied integer relations."""
    v=derive(p,4); count=p.schema.dimension; n=v['n']; r.vector(quotient,count); r.vector(remainder,count)
    need(type(xs) is list and len(xs)==count and all(type(x) is int for x in xs) and type(scale) is int and scale>=0,'Input')
    mags=[abs(x) for x in xs]+[0]*(n-count); qs=quotient+[0]*(n-count); rs=remainder+[0]*(n-count); incoming=[0]*n; carry=[]
    for j in range(v['planes']):
        next_c=[]
        for i in range(n):
            sb=scale>>(8*j)&255 if i<count else 0
            numerator=2*sb*qs[i]+(rs[i]>>(8*j)&255)+incoming[i]-2*(mags[i]>>(8*j)&255)-sb
            need(numerator%256==0,'Witness'); next_c.append(numerator//256)
        incoming=next_c; carry.extend(x+3 for x in incoming)
    return carry


def witness(p,xs):
    v=derive(p,4); _,scale,_,_=ds.witness(v['scale'],xs); active=int(scale>0)
    pairs=[divmod(2*abs(x)+scale,2*scale) if scale else (0,0) for x in xs]; q=[x[0] for x in pairs]; rem=[x[1] for x in pairs]
    return dict(scale=scale,codes=[-value if x<0 else value for x,value in zip(xs,q)],quotient=q,remainder=rem,
                remainder_gap=[2*scale-active-x for x in rem],zero_gap=[127*active-x for x in q],
                nonzero=[active],predecessor=[scale-1 if active else 0],carry=carry_words(p,xs,scale,q,rem))


def unpack(child,words,d):
    """Linear view of actual byte planes; the caller verifies their range first."""
    _,_,n,width,_,_=r.derive(child,d); r.vector(words,n*width)
    return [sum(words[j*n+i]<<(8*j) for j in range(width)) for i in range(n)]


def roots(p,proof):
    v=derive(p,4)
    return ds.roots(v['scale'],proof['scale'])+[r.source_root(ss.derive(v['output'],4)['ranges'][0],proof['output']['ranges'][0]['words'])]


def bound(expected,proof):
    return expected+[proof['roots'][name] for name in AUX]


def parts(p,proof,d):
    v=derive(p,d); n,width,planes,base=v['n'],v['width'],v['planes'],v['base']; count=p.schema.dimension
    scale_words=proof['scale']['scale']['words']; source=proof['scale']['maximum']['input']['ranges']
    mag=source[1]['words']; sin=source[2]['words']; sout=proof['output']['ranges'][2]['words']; q=proof['quotient']['words']
    for xs,size in ((scale_words,width),(mag,n*width),(sin,2*n),(sout,2*n),(q,n)): r.vector(xs,size)
    values={name:unpack(v[name],proof[name]['words'],d) for name in RANGES[1:]}
    scale=unpack(ds.derive(v['scale'],d)['scale'],scale_words,d)[0]; active=values['nonzero'][0]; pred=values['predecessor'][0]
    sm=[scale if i<count else 0 for i in range(n)]; nm=[active if i<count else 0 for i in range(n)]; carry=values['carry']
    sb=[scale_words[j] if j<width and i<count else 0 for j in range(planes) for i in range(n)]
    rem=proof['remainder']['words']; r.vector(rem,n*width); high=[0]*(n*(planes-width))
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=4194304*p.identity+3145728+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(x,d),factors) for x,factors in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in rows]
    return [item('ScaleNonzero',0,0,[base+32,base+5,base+33],[(1,[0]),(-1,[1,2]),(-1,[1])],[[scale],[active],[pred]]),
            item('PredecessorCanonical',1,0,[base+5,base+33],[(1,[1]),(-1,[0,1])],[[active],[pred]]),
            item('RemainderBound',2,v['a'],[base+34,base+35,base+36,base+37],[(1,[0]),(1,[1]),(1,[2]),(-2,[3])],
                 [values['remainder'],values['remainder_gap'],nm,sm]),
            item('ZeroCode',3,v['a'],[base+1,base+4,base+36],[(1,[0]),(1,[1]),(-127,[2])],[q,values['zero_gap'],nm]),
            item('RoundedDivision',4,v['a']+v['c'],list(range(base+38,base+44)),
                 [(2,[0,1]),(1,[2]),(-2,[3]),(-1,[0]),(1,[4]),(-256,[5]),(765,[])],
                 [sb,q*planes,rem+high,mag+high,[3]*n+carry[:-n],carry]),
            item('TerminalCarry',5,v['a'],[base+44],[(1,[0]),(-3,[])],[carry[-n:]]),
            item('SignTransfer',6,v['a'],[base+45,base+46,base+1],[(1,[0,2]),(-1,[1,2])],[sin[:n],sout[:n],q])]


def transcript(p,bounds,states,d):
    need(type(bounds) is list and len(bounds)==10 and type(states) is list and len(states)==9 and
         all(type(x) is bytes and len(x)==32 for x in bounds+states),'Root')
    return r.scalar.Transcript(derive(p,d)['raw']+b''.join(bounds+states),d)


def prepare(p,xs,d):
    v=derive(p,d); w=witness(p,xs)
    return dict(scale=ds.prove(v['scale'],xs,d),output=ss.prove(v['output'],w['codes'],d),
                **{name:r.prove(v[name],w[name],d) for name in RANGES})


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; only verify authorizes a statement."""
    v=derive(p,d); proof={name:pairs[name][0] for name in NAMES}
    proof['roots']=dict(magnitude=r.root(v['base']+1,proof['output']['ranges'][1]['words']),
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
    need(type(proof['zero']) is list and len(proof['zero'])==7,'ProofShape'); children=[]
    targets=[expected[:2],[expected[2],proof['roots']['magnitude']]]+[proof['roots'][name] for name in AUX]
    for name,target,verifier in zip(NAMES,targets,(ds.verify,ss.verify)+(r.verify,)*7):
        try: children.append(verifier(v[name],target,proof[name],d))
        except ValueError as error: raise ValueError(name.title().replace('_','')+':'+str(error)) from None
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
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),
                    selection_reduction_numerator=accounts[0]['selection_reduction_numerator'],denominator=r.sc.P**d))
