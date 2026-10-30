"""Q26/Q31 signed sources: RFC-0004 A1 / Draft A3, revealing consumed research.

O(NB) witness and A3 producer work; inherited full-opening verifiers are reference.
"""
from dataclasses import dataclass
import struct
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/signed-source/v1\0'


@dataclass(frozen=True)
class Spec:
    identity: int
    source: int
    magnitude: int
    bits: int
    count: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<53 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.bits) is int and p.bits in (8,16,32) and type(p.count) is int and p.count>=1,'Spec')
    need(p.count<=2048,'Capacity')
    a=(p.count-1).bit_length(); n=1<<a; width=p.bits//8; b=width.bit_length()-1
    base=(1<<63)+512*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+512 for x in (p.source,p.magnitude)) and p.source!=p.magnitude,'Spec')
    caps=[((1<<p.bits)-1,)*p.count,(1<<(p.bits-1),)*p.count,
          (1,)*p.count+(0,)*(n-p.count)+(127,)*p.count+(0,)*(n-p.count)]
    ranges=[r.Spec(8*p.identity+j+1,source,cap,p.repetitions) for j,(source,cap) in enumerate(zip((p.source,p.magnitude,base),caps))]
    for child in ranges: r.derive(child,d)
    # A1 integer faithfulness is per byte; no signed int32 is embedded in M31.
    need(2*511<r.sc.P,'FieldBound')
    raw=PREFIX+struct.pack('<BBBQQQBI',1,d,p.repetitions,p.identity,p.source,p.magnitude,p.bits,p.count)
    return dict(a=a,b=b,n=n,width=width,base=base,ranges=ranges,raw=raw)


def witness(p,xs):
    v=derive(p,4); high=1<<(p.bits-1); n,width=v['n'],v['width']
    need(type(xs) is list and len(xs)==p.count and all(type(x) is int and -high<=x<high for x in xs),'Input')
    raw=[x%(1<<p.bits) for x in xs]; mag=[abs(x) for x in xs]
    us=raw+[0]*(n-p.count); ms=mag+[0]*(n-p.count); signs=[int(x<0) for x in xs]+[0]*(n-p.count)
    sign=signs+[(u>>(8*(width-1)))&127 for u in us]; cs=[]; incoming=[0]*n
    for j in range(width):
        incoming=[signs[i]*(((us[i]>>(8*j)&255)+(ms[i]>>(8*j)&255)+incoming[i])//256) for i in range(n)]
        cs.extend(incoming)
    return raw,mag,sign,cs


def roots(p,words,cs):
    v=derive(p,4); need(type(words) is list and len(words)==3,'ProofShape'); r.vector(cs,v['n']*v['width'])
    return [r.source_root(child,xs) for child,xs in zip(v['ranges'],words)]+[r.root(v['base']+1,cs)]


def parts(p,words,cs,d):
    v=derive(p,d); n,width,base=v['n'],v['width'],v['base']; count=n*width
    need(type(words) is list and len(words)==3,'ProofShape')
    for xs,size in zip(words+[cs],(count,count,2*n,count)): r.vector(xs,size)
    us,ms,sv=words; signs=sv[:n]; broadcast=signs*width; cin=[0]*n+cs[:count-n]
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=32*p.identity+24+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(c,d),factors) for c,factors in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in rows]
    return [item('TopBit',0,v['a'],[base+8,base+9,base+10],[(1,[0]),(-128,[1]),(-1,[2])],[us[count-n:],signs,sv[n:]]),
            item('Positive',1,v['a']+v['b'],[p.source,p.magnitude,base+11],
                 [(1,[0]),(-1,[1]),(-1,[2,0]),(1,[2,1])],[us,ms,broadcast]),
            item('Negative',2,v['a']+v['b'],[base+11,p.source,p.magnitude,base+12,base+1],
                 [(1,[0,1]),(1,[0,2]),(1,[0,3]),(-256,[0,4])],[broadcast,us,ms,cin,cs]),
            item('CarryBoolean',3,v['a']+v['b'],[base+1],[(1,[0,0]),(-1,[0])],[cs]),
            item('CarryInactive',4,v['a']+v['b'],[base+11,base+1],[(1,[1]),(-1,[0,1])],[broadcast,cs]),
            item('Terminal',5,v['a'],[base+13,base+9],[(1,[0]),(-1,[1])],[cs[count-n:],signs])]


def transcript(p,bound,states,d):
    need(type(bound) is list and len(bound)==4 and type(states) is list and len(states)==3 and
         all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(derive(p,d)['raw']+b''.join(bound+states),d)


def ranges(p,xs,d):
    v=derive(p,d); raw,mag,sign,cs=witness(p,xs)
    return [r.prove(child,values,d) for child,values in zip(v['ranges'],(raw,mag,sign))],cs


def assemble(p,pairs,cs,d):
    """Arithmetic producer for supplied proofs/vectors; full acceptance is verify."""
    words=[pair[0]['words'] for pair in pairs]; bound=roots(p,words,cs)
    t=transcript(p,bound,[pair[1] for pair in pairs],d)
    proof=dict(ranges=[pair[0] for pair in pairs],sign_root=bound[2],carry_root=bound[3],carry=list(cs),
               zero=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,words,cs,d)])
    return proof,t.state


def prove(p,xs,d):
    return assemble(p,*ranges(p,xs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'ranges','sign_root','carry_root','carry','zero'},'ProofShape')
    need(all(type(proof[k]) is bytes and len(proof[k])==32 for k in ('sign_root','carry_root')),'Root')
    need(type(proof['ranges']) is list and len(proof['ranges'])==3 and type(proof['zero']) is list and len(proof['zero'])==6,'ProofShape')
    r.vector(proof['carry'],v['n']*v['width'])
    need(r.root(v['base']+1,proof['carry'])==proof['carry_root'],'Carry:CommitmentMismatch')
    bound=expected+[proof['sign_root'],proof['carry_root']]; children=[]
    for name,child,root,part in zip(('Raw','Magnitude','Sign'),v['ranges'],bound,proof['ranges']):
        try: children.append(r.verify(child,root,part,d))
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
    t=transcript(p,bound,[child['state'] for child in children],d); records=[]; claims=[]
    words=[part['words'] for part in proof['ranges']]
    for (name,i,tables),part in zip(parts(p,words,proof['carry'],d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
             all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and
             type(part['final']) is list and len(part['final'])==len(i['ids']) and
             all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        # The reference A3 consumer checks every view MLE from these rooted arrays,
        # including originals multiplied by zero in an inactive sign branch.
        try: receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children]
    return dict(state=t.state,ranges=children,sc=records,claims=claims,draws=dict(t.draws),
                account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],
                    lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),
                    denominator=r.sc.P**d))
