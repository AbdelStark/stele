"""Draft RFC-0004 A3/A6 / RFC-0009 A2: strict attention magnitude division.

Complete Qp=qD, W=2U+D and D2=2D children share one expected D root.
Two faithful byte relations consume all ten actual parent originals.
"""
from dataclasses import dataclass
import struct
import attention_quotient_product as qp
import attention_biased_numerator as bias
import attention_doubled_denominator as double

bounds=qp.bounds
r=qp.r
need=r.need
PREFIX=b'stele/research/q26/attention-division/v1\0'
CHILDREN=(('quotient_product',qp,(2,1,3),'QuotientProduct'),('bias',bias,(0,1,4),'Bias'),('double',double,(1,5),'Double'))


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    numerator: int
    denominator: int
    quotient: int
    product: int
    biased: int
    doubled: int
    remainder: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<38 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');a=(p.schema.width-1).bit_length();n=1<<a;base=(1<<63)+(1<<24)*p.identity;ids=(p.numerator,p.denominator,p.quotient,p.product,p.biased,p.doubled,p.remainder)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<24) for x in ids) and len(set(ids))==7,'Spec')
    children=dict(quotient_product=qp.Spec(p.schema,1024*p.identity+1,p.quotient,p.denominator,p.product,p.repetitions),bias=bias.Spec(p.schema,1024*p.identity+2,p.numerator,p.denominator,p.biased,p.repetitions),double=double.Spec(p.schema,64*p.identity+1,p.denominator,p.doubled,p.repetitions))
    for name,module,_,_ in CHILDREN:module.derive(children[name],d)
    limit=constants['remainder_max'];need(limit==2*constants['denominator_max']-1 and max(constants[name] for name in ('biased_max','scaled_quotient_max','double_denominator_max'))<1<<128,'Capacity');need(2*767<r.sc.P and 2*511<r.sc.P,'FieldBound')
    br=(max(1,(limit.bit_length()+7)//8)-1).bit_length();groups=1 if n*(1<<br)<=131072 else 2;size=n//groups;caps={}
    for role in ('remainder','gap'):
        for j in range(groups):
            real=min(size,p.schema.width-j*size);caps[role+'_'+str(j)]=(limit,)*real+(0,)*(size-real if groups==2 else 0)
    for role,cap in (('equal',2),('strict',1)):
        for j in range(4):caps[role+'_'+str(j)]=tuple(cap if i<p.schema.width and 4*j+k<15 else 0 for k in range(4) for i in range(n))
    ranges={name:r.Spec(262144*p.identity+index,base+index,cap,p.repetitions) for index,(name,cap) in enumerate(caps.items(),1)};layouts={name:r.derive(child,d) for name,child in ranges.items()}
    need(all(layouts[role+'_'+str(j)][2:4]==(size,1<<br) for role in ('remainder','gap') for j in range(groups)) and all(layouts[role+'_'+str(j)][2:4]==(4*n,1) for role in ('equal','strict') for j in range(4)),'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQQQQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(constants=constants,ranges=ranges,a=a,n=n,groups=groups,br=br,base=base,raw=raw,**children)


def witness(p,us,D,qs,rs):
    v=derive(p,4);need(type(D) is int and 1<=D<=v['constants']['denominator_max'],'Input')
    for xs,cap in ((us,v['constants']['numerator_max']),(qs,32768),(rs,2*D-1)):need(type(xs) is list and len(xs)==p.schema.width and all(type(x) is int and 0<=x<=cap for x in xs),'Input')
    need(all(2*u+D==2*q*D+rest for u,q,rest in zip(us,qs,rs)),'Input');n=v['n'];size=n//v['groups'];gap=[2*D-1-x for x in rs];w={}
    for role,values in (('remainder',rs),('gap',gap)):
        for j in range(v['groups']):
            part=values[j*size:(j+1)*size];w[role+'_'+str(j)]=part+[0]*(size-len(part) if v['groups']==2 else 0)
    for role,left,right,factor,initial in (('equal',[q*D for q in qs],rs,2,0),('strict',rs,gap,1,1)):
        left=left+[0]*(n-len(left));right=right+[0]*(n-len(right));carry=[initial]*p.schema.width+[0]*(n-p.schema.width);cs=[]
        for k in range(16):
            carry=[(factor*(x>>(8*k)&255)+(y>>(8*k)&255)+old)//256 for x,y,old in zip(left,right,carry)];cs.extend(carry)
        for j in range(4):w[role+'_'+str(j)]=cs[4*j*n:4*(j+1)*n]
    return w


def full(v,proof,role):
    size=v['n']//v['groups'];groups=[]
    for j in range(v['groups']):
        name=role+'_'+str(j);compact=r.derive(v['ranges'][name],4)[3];words=proof[name]['words'];r.vector(words,size*compact);groups.append(words+[0]*(size*(16-compact)))
    return [x for k in range(16) for group in groups for x in group[k*size:(k+1)*size]]


def roots(p,proof):
    v=derive(p,4);qr=qp.roots(v['quotient_product'],proof['quotient_product']);br=bias.roots(v['bias'],proof['bias']);dr=double.roots(v['double'],proof['double']);need(qr[1]==br[1]==dr[0],'Denominator:SourceJoin')
    return [br[0],qr[1],qr[0],qr[2],br[2],dr[1],r.root(p.remainder,full(v,proof,'remainder'))]


def expected_roots(p,us,D,qs,rs):
    v=derive(p,4);witness(p,us,D,qs,rs);qr=qp.expected_roots(v['quotient_product'],qs,D);br=bias.expected_roots(v['bias'],us,D);dr=double.expected_roots(v['double'],D)
    words=[x>>(8*k)&255 for k in range(16) for x in rs+[0]*(v['n']-len(rs))];return [br[0],qr[1],qr[0],qr[2],br[2],dr[1],r.root(p.remainder,words)]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];qv=qp.derive(v['quotient_product'],d);bv=bias.derive(v['bias'],d);dv=double.derive(v['double'],d);den=double.output(dv,proof['double']['double']['output']['words']);remainder=full(v,proof,'remainder');items=[]
    for index,role in enumerate(('equal','strict')):
        carry=[]
        for j in range(4):words=proof[role+'_'+str(j)]['words'];r.vector(words,4*n);carry.extend(words)
        # Draft A6: strict initial one and shared D2 are masked to real rows.
        incoming=[index]*p.schema.width+[0]*(n-p.schema.width)+carry[:-n]
        rows=(qp.full(qv,proof['quotient_product']),remainder,incoming,bias.full(bv,proof['bias'],'biased'),carry) if index==0 else (remainder,full(v,proof,'gap'),incoming,[den[k] if row<p.schema.width else 0 for k in range(16) for row in range(n)],carry)
        i=dict(id=1048576*p.identity+32768+index,m=v['a']+4,k=0,ids=[v['base']+32+5*index+j for j in range(5)],terms=[(r.sc.scalar(coefficient,d),[j]) for j,coefficient in enumerate((2-index,1,1,-1,-256))])
        items.append(('Equality' if index==0 else 'StrictRemainder',i,[[r.sc.scalar(x,d) for x in row] for row in rows]))
    return items


def transcript(v,bound,states,d):
    count=len(v['ranges']);need(type(bound) is list and len(bound)==7+count and type(states) is list and len(states)==3+count and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root');return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,us,D,qs,rs,d):
    v=derive(p,d);w=witness(p,us,D,qs,rs);return dict(quotient_product=qp.prove(v['quotient_product'],qs,D,d),bias=bias.prove(v['bias'],us,D,d),double=double.prove(v['double'],D,d),**{name:r.prove(child,w[name],d) for name,child in v['ranges'].items()})


def assemble(p,pairs,d):
    """Producer only; complete children, shared roots and originals are required."""
    v=derive(p,d);names=[name for name,_,_,_ in CHILDREN]+list(v['ranges']);proof={name:pairs[name][0] for name in names};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in v['ranges']],[pairs[name][1] for name in names],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)];return proof,t.state


def prove(p,us,D,qs,rs,d):
    return assemble(p,prepare(p,us,D,qs,rs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);names=tuple(v['ranges']);need(type(expected) is list and len(expected)==7 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(names)|{'quotient_product','bias','double','roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(names) and type(proof['zero']) is list and len(proof['zero'])==2,'ProofShape');need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[];ranges=[]
    for name,module,indices,label in CHILDREN:
        try:children.append(module.verify(v[name],[expected[j] for j in indices],proof[name],d))
        except ValueError as error:raise ValueError(label+':'+str(error)) from None
    for name,child in v['ranges'].items():
        try:ranges.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    need(r.root(p.remainder,full(v,proof,'remainder'))==expected[6],'Remainder:CommitmentMismatch');t=transcript(v,expected+[proof['roots'][name] for name in names],[child['state'] for child in children+ranges],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==2 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==5 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    inherited=[child['account'] for child in children];accounts=[child['account'] for child in ranges]
    return dict(state=t.state,children=children,ranges=ranges,sc=records,claims=claims,draws=dict(t.draws),account=dict(identities=sum((x['identities'] for x in inherited),[])+[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in inherited+accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in inherited+accounts)+sum(x['numerator'] for x in records),product_identity_numerator=inherited[2]['product_identity_numerator'],product_reduction_numerator=inherited[2]['product_reduction_numerator'],denominator=r.sc.P**d))
