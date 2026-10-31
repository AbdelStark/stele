"""Draft RFC-0004 A3/A8: exact residual magnitude quotient and strict remainder.

O(N) byte/carry views and two batched A3s plus complete range/hash consumers.
Expected dyadic units fix both the divisor and rounding bias.
"""
from dataclasses import dataclass
import struct
import residual_bounds as residual
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/residual-rounding/v1\0'
NAMES=('magnitude','quotient','remainder','carry_0','carry_1')
EXTERNAL_WIDTHS=(8,2,4)


@dataclass(frozen=True)
class Spec:
    schema: residual.Spec
    identity: int
    magnitude: int
    quotient: int
    remainder: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=residual.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.dimension;need(count<=16384,'Capacity');a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=(p.magnitude,p.quotient,p.remainder)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==3,'Spec')
    caps=[(constants['numerator_max'],)*count,(32768,)*count,(constants['remainder_max'],)*count]+[((131,)*count+(0,)*(n-count))*4]*2
    ranges={name:r.Spec(256*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(zip(NAMES,caps),1)}
    widths={name:r.derive(child,d)[3] for name,child in ranges.items()}
    need(widths['magnitude']<=8 and widths['quotient']==2 and widths['remainder']<=4 and widths['carry_0']==widths['carry_1']==1,'Capacity')
    need(2*66431<r.sc.P,'FieldBound');s=p.schema
    raw=PREFIX+struct.pack('<BBBQQQQIBBB',1,d,p.repetitions,p.identity,*ids,count,s.left_fraction,s.right_fraction,s.output_fraction)
    return dict(constants=constants,divisor=constants['divisor'],bias=constants['bias'],shift=constants['divisor'].bit_length()-1,ranges=ranges,widths=widths,a=a,n=n,base=base,raw=raw)


def carries(p,magnitudes,quotients,remainders):
    """Producer only; supports coherent false remainders for rejection controls."""
    v=derive(p,4);count=p.schema.dimension;n=v['n'];shift=v['shift'];h=v['bias']
    need(all(type(row) is list and len(row)==count and all(type(x) is int and 0<=x<1<<(8*width) for x in row) for row,width in zip((magnitudes,quotients,remainders),EXTERNAL_WIDTHS)),'Input')
    M=magnitudes+[0]*(n-count);Q=quotients+[0]*(n-count);R=remainders+[0]*(n-count);carry=[0]*n;cs=[]
    for k in range(8):
        qb=[(x>>(8*(k-shift//8))&255)*(1<<(shift%8)) for x in Q] if shift//8<=k<shift//8+2 else [0]*n
        diff=[(M[i]>>(8*k)&255)+((h>>(8*k)&255) if i<count else 0)-qb[i]-(R[i]>>(8*k)&255)+carry[i] for i in range(n)]
        need(all(x%256==0 for x in diff),'ColumnRemainder');carry=[x//256 for x in diff]
        need(all(-129<=x<=2 for x in carry),'CarryRange');cs.extend(carry[i]+129 if i<count else 0 for i in range(n))
    need(not any(carry),'TerminalCarry');return cs


def witness(p,magnitudes):
    v=derive(p,4);count=p.schema.dimension;n=v['n']
    need(type(magnitudes) is list and len(magnitudes)==count and all(type(x) is int and 0<=x<=v['constants']['numerator_max'] for x in magnitudes),'Input')
    qr=[divmod(m+v['bias'],v['divisor']) for m in magnitudes];qs=[q for q,_ in qr];rs=[rem for _,rem in qr]
    need(all(q<=32768 for q in qs),'QuotientRange');cs=carries(p,magnitudes,qs,rs)
    return dict(magnitude=magnitudes.copy(),quotient=qs,remainder=rs,carry_0=cs[:4*n],carry_1=cs[4*n:])


def full_words(v,proof,name,width):
    words=proof[name]['words'];r.vector(words,v['widths'][name]*v['n']);return words+[0]*((width-v['widths'][name])*v['n'])


def roots(p,proof):
    v=derive(p,4)
    return [r.root(identity,full_words(v,proof,name,width)) for identity,name,width in zip((p.magnitude,p.quotient,p.remainder),NAMES,EXTERNAL_WIDTHS)]


def expected_roots(p,magnitudes,quotients,remainders):
    v=derive(p,4);count=p.schema.dimension;rows=(magnitudes,quotients,remainders)
    need(all(type(row) is list and len(row)==count and all(type(x) is int and 0<=x<1<<(8*width) for x in row) for row,width in zip(rows,EXTERNAL_WIDTHS)),'Input')
    def planes(values,width):return [x>>(8*k)&255 for k in range(width) for x in values+[0]*(v['n']-count)]
    return [r.root(identity,planes(row,width)) for identity,row,width in zip((p.magnitude,p.quotient,p.remainder),rows,EXTERNAL_WIDTHS)]


def parts(p,proof,d):
    v=derive(p,d);n,base=v['n'],v['base'];count=p.schema.dimension;shift=v['shift'];h=v['bias'];M=full_words(v,proof,'magnitude',8);Q=full_words(v,proof,'quotient',2);R=full_words(v,proof,'remainder',4)+[0]*(4*n);carry=[]
    for name in ('carry_0','carry_1'):r.vector(proof[name]['words'],4*n);carry.extend(proof[name]['words'])
    endpoint=[129 if i<count else 0 for i in range(n)]
    public=[(h>>(8*k)&255)+32895 if i<count else 0 for k in range(8) for i in range(n)]
    product=[Q[(k-shift//8)*n+i]*(1<<(shift%8)) if shift//8<=k<shift//8+2 else 0 for k in range(8) for i in range(n)]
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=1024*p.identity+128+index,m=m,k=0,ids=ids,terms=[(r.sc.scalar(value,d),factors) for value,factors in terms]),[[r.sc.scalar(x,d) for x in row] for row in rows]
    # c'=c+129 changes the signed carry equation by +255*129.
    # Actual quotient bytes supply q*B; no wide product is embedded in M31.
    return [item('TerminalCarry',0,v['a'],[base+22,base+23],[(1,[0]),(-1,[1])],[carry[7*n:],endpoint]),
            item('RoundColumns',1,v['a']+3,list(range(base+16,base+22)),[(1,[0]),(1,[1]),(1,[2]),(-1,[3]),(-1,[4]),(-256,[5])],[M,public,endpoint+carry[:-n],product,R,carry])]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==8 and type(states) is list and len(states)==5 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,magnitudes,d):
    v=derive(p,d);w=witness(p,magnitudes);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; supplied states and coherent false columns grant no acceptance."""
    v=derive(p,d);proof={name:pairs[name][0] for name in NAMES};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in NAMES],[pairs[name][1] for name in NAMES],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,magnitudes,d):
    return assemble(p,prepare(p,magnitudes,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(NAMES) and type(proof['zero']) is list and len(proof['zero'])==2,'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for name,actual,target in zip(('Magnitude','Quotient','Remainder'),roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    t=transcript(v,expected+[proof['roots'][name] for name in NAMES],[child['state'] for child in children],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==len(i['ids']) and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children];account=dict(identities=[(item['identity_numerator'],item['identity_power']) for item in accounts],lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in accounts),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in accounts)+sum(row['numerator'] for row in records),denominator=r.sc.P**d)
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),account=account)
