"""Q26/Q31 strict remainder: RFC-0021 §2.3 / Draft RFC-0004 A3.

Three complete scalar byte ranges and fixed16-column carry consumers.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import function_identity as fn

need=r.need
NAMES=('divisor','remainder','gap')
PREFIX=b'stele/research/q26/norm-remainder/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    divisor: int
    remainder: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<50 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=norm.constants(p.schema);need(0<cert['D_max']<1<<124 and 2*511<r.sc.P,'FieldBound')
    base=(1<<63)+4096*p.identity;ids=(p.divisor,p.remainder)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+4096 for x in ids) and len(set(ids))==2,'Spec')
    ranges={name:r.Spec(64*p.identity+j+1,base+j+1,(cert['D_max']-int(j>0),),p.repetitions) for j,name in enumerate(NAMES)}
    for child in ranges.values():r.derive(child,d)
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQ',1,d,p.repetitions,p.identity,*ids)+fn.encode(function)
    return dict(cert=cert,base=base,ranges=ranges,raw=raw)


def external(words):
    need(type(words) is list and len(words) in (1,2,4,8,16),'OpeningShape');r.vector(words,len(words))
    return words+[0]*(16-len(words))


def carries(remainder,gap):
    """Producer arithmetic; boolean/terminal/column consumers still verify it."""
    need(all(type(x) is int and 0<=x<1<<128 for x in (remainder,gap)),'Range')
    carry=1;result=[]
    for j in range(16):carry=((remainder>>(8*j)&255)+(gap>>(8*j)&255)+carry)//256;result.append(carry)
    return result


def expected_roots(p,divisor,remainder):
    derive(p,4);need(all(type(x) is int and 0<=x<1<<128 for x in (divisor,remainder)),'Range')
    return [r.root(identity,list(value.to_bytes(16,'little'))) for identity,value in ((p.divisor,divisor),(p.remainder,remainder))]


def roots(p,proof,d):
    v=derive(p,d);children=[];words=[]
    for name in NAMES:
        part=proof[name];need(type(part) is dict and 'words' in part,'ProofShape')
        children.append(r.source_root(v['ranges'][name],part['words']));words.append(external(part['words']))
    r.vector(proof['carry'],16)
    return [r.root(p.divisor,words[0]),r.root(p.remainder,words[1])]+children+[r.root(v['base']+4,proof['carry'])]


def parts(p,proof,d):
    v=derive(p,d);base=v['base'];cs=proof['carry'];r.vector(cs,16)
    divisor,remainder,gap=[external(proof[name]['words']) for name in NAMES]
    def item(name,j,m,ids,terms,rows):
        return name,dict(id=256*p.identity+128+j,m=m,k=0,ids=ids,terms=[(r.sc.scalar(c,d),f) for c,f in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in rows]
    return [item('CarryBoolean',0,4,[base+4],[(1,[0,0]),(-1,[0])],[cs]),
            item('TerminalCarry',1,0,[base+8],[(1,[0])],[[cs[-1]]]),
            item('StrictColumns',2,4,[base+9,base+10,base+11,base+12,base+4],
                 [(1,[0]),(1,[1]),(1,[2]),(-1,[3]),(-256,[4])],[remainder,gap,[1]+cs[:-1],divisor,cs])]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==6 and type(states) is list and len(states)==3 and
         all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,divisor,remainder,d):
    v=derive(p,d);need(type(divisor) is int and 1<=divisor<=v['cert']['D_max'] and type(remainder) is int and 0<=remainder<divisor,'Range')
    gap=divisor-remainder-1
    return {name:r.prove(v['ranges'][name],[value],d) for name,value in zip(NAMES,(divisor,remainder,gap))},carries(remainder,gap)


def assemble(p,pairs,cs,d):
    """Producer may build false arithmetic; only complete verify accepts it."""
    v=derive(p,d);proof={name:pairs[name][0] for name in NAMES};proof['carry']=list(cs)
    t=transcript(v,roots(p,proof,d),[pairs[name][1] for name in NAMES],d)
    proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,divisor,remainder,d):
    return assemble(p,*prepare(p,divisor,remainder,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(NAMES)|{'carry','zero'} and type(proof['zero']) is list and len(proof['zero'])==3,'ProofShape')
    bound=roots(p,proof,d)
    for name,actual,target in zip(('Divisor','Remainder'),bound,expected):need(actual==target,name+':CommitmentMismatch')
    children=[]
    for j,name in enumerate(NAMES):
        try:children.append(r.verify(v['ranges'][name],bound[j+2],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(v,bound,[child['state'] for child in children],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds'])
             and type(part['final']) is list and len(part['final'])==len(i['ids']) and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    accounts=[child['account'] for child in children]
    return dict(state=t.state,ranges=children,draws=dict(t.draws),sc=records,claims=claims,
        account=dict(identities=[(a['identity_numerator'],a['identity_power']) for a in accounts],lookup_reduction_numerator=sum(a['lookup_reduction_numerator'] for a in accounts),
            range_reduction_numerator=sum(a['range_reduction_numerator'] for a in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
