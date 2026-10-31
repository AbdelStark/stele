"""RFC-0022 §2.3 output division / revealing Draft RFC-0004 A3.

O(16N) equality/strict views, with complete quotient-product, bias and ranges.
Actual B/h still require configured-factor and selected-branch authentication.
"""
from dataclasses import dataclass
import struct
import norm_quotient_product as qp
import norm_bias as bias
import function_identity as fn

norm=qp.norm
r=qp.r
need=r.need
PREFIX=b'stele/research/q26/norm-division/v1\0'
MASK=(1<<64)-1


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    quotient: int
    divisor: int
    scaled: int
    product: int
    bias: int
    total: int
    remainder: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<40 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.d;a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<22)*p.identity;external=(p.quotient,p.divisor,p.scaled,p.product,p.bias,p.total,p.remainder)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<22) for x in external) and len(set(external))==7,'Spec')
    quotient=qp.Spec(p.schema,16*p.identity+1,p.quotient,p.divisor,p.scaled,p.repetitions);biased=bias.Spec(p.schema,16*p.identity+2,p.product,p.bias,p.total,p.repetitions)
    qp.derive(quotient,d);bias.derive(biased,d);limit=constants['round_divisor_max'];cert=norm.limbs.derive(norm.column_specs(p.schema)['division'])
    # RFC-0022 §2.3: the strict relation adds one, so its initial carry is one.
    equal=list(cert['carry_caps'])+[0]*(17-len(cert['carry_caps']));strict=[1]
    for k in range(16):strict.append((2*min(255,(limit-1)>>(8*k))+strict[-1])//256)
    need(len(equal)==17 and equal[0]==equal[-1]==strict[-1]==0 and all(x in (0,1) for x in equal+strict) and 2*511<r.sc.P,'FieldBound')
    def child(index,caps):return r.Spec(65536*p.identity+index,base+index,tuple(caps),p.repetitions)
    ranges={}
    for prefix,index in (('remainder',1),('gap',3)):
        ranges[prefix+'_low']=child(index,[min(limit-1,MASK)]*count)
        if (limit-1)>>64:ranges[prefix+'_high']=child(index+1,[(limit-1)>>64]*count)
    for prefix,index,caps in (('equal',5,equal),('strict',9,strict)):
        for g in range(4):
            family=caps[1+4*g:5+4*g]
            if any(family):ranges[prefix+'_'+str(g)]=child(index+g,[cap if i<count else 0 for cap in family for i in range(n)])
    widths={name:r.derive(child,d)[3] for name,child in ranges.items()};need(all(widths[name]<=8 for name in widths),'Capacity')
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQQQQQ',1,d,p.repetitions,p.identity,*external)+fn.encode(function)
    return dict(quotient_product=quotient,bias=biased,ranges=ranges,widths=widths,equal_caps=equal,strict_caps=strict,a=a,n=n,base=base,limit=limit,raw=raw)


def witness(p,ts,h,qs,b,rs):
    v=derive(p,4);qp.inputs(v['quotient_product'],qp.derive(v['quotient_product'],4),qs,b);bias.inputs(v['bias'],bias.derive(v['bias'],4),ts,h)
    need(type(rs) is list and len(rs)==p.schema.d and all(type(x) is int and 0<=x<b and q*b+x==t+h for x,q,t in zip(rs,qs,ts)),'Input');n=v['n'];w={}
    for prefix,xs in (('remainder',rs),('gap',[b-1-x for x in rs])):
        w[prefix+'_low']=[x&MASK for x in xs]
        if prefix+'_high' in v['ranges']:w[prefix+'_high']=[x>>64 for x in xs]
    for prefix,left,right,first in (('equal',[q*b for q in qs],rs,0),('strict',rs,[b-1-x for x in rs],1)):
        left=left+[0]*(n-p.schema.d);right=right+[0]*(n-p.schema.d);carry=[first]*p.schema.d+[0]*(n-p.schema.d);values=[]
        for k in range(16):
            carry=[((x>>(8*k)&255)+(y>>(8*k)&255)+c)//256 for x,y,c in zip(left,right,carry)];values.extend(carry)
        for g in range(4):
            name=prefix+'_'+str(g)
            if name in v['ranges']:w[name]=values[4*g*n:4*(g+1)*n]
    return w


def wide_words(v,proof,prefix):
    result=[]
    for half in ('low','high'):
        name=prefix+'_'+half
        if name in v['ranges']:
            words=proof[name]['words'];r.vector(words,v['widths'][name]*v['n']);result.extend(words+[0]*((8-v['widths'][name])*v['n']))
        else:result.extend([0]*(8*v['n']))
    return result


def roots(p,proof):
    v=derive(p,4)
    return qp.roots(v['quotient_product'],proof['quotient_product'])+bias.roots(v['bias'],proof['bias'])+[r.root(p.remainder,wide_words(v,proof,'remainder'))]


def expected_roots(p,ts,h,qs,b,rs):
    v=derive(p,4);witness(p,ts,h,qs,b,rs)
    words=[x>>(8*k)&255 for k in range(16) for x in rs+[0]*(v['n']-len(rs))]
    return qp.expected_roots(v['quotient_product'],qs,b,[q*b for q in qs])+bias.expected_roots(v['bias'],ts,h,[t+h for t in ts])+[r.root(p.remainder,words)]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];qv=qp.derive(v['quotient_product'],d);bv=bias.derive(v['bias'],d);remainder=wide_words(v,proof,'remainder');bs=qp.divisor_words(qv,proof['quotient_product']);items=[]
    for index,prefix in enumerate(('equal','strict')):
        carry=[]
        for g in range(4):
            name=prefix+'_'+str(g)
            if name in v['ranges']:r.vector(proof[name]['words'],4*n);carry.extend(proof[name]['words'])
            else:carry.extend([0]*(4*n))
        # Expected row count masks both scalar B and the strict initial one.
        initial=[index]*p.schema.d+[0]*(n-p.schema.d)
        if index==0:rows=[qp.output_words(qv,proof['quotient_product']),remainder,initial+carry[:15*n],bias.output_words(bv,proof['bias']),carry]
        else:rows=[remainder,wide_words(v,proof,'gap'),initial+carry[:15*n],[bs[k] if row<p.schema.d else 0 for k in range(16) for row in range(n)],carry]
        i=dict(id=262144*p.identity+65536+index,m=v['a']+4,k=0,ids=list(range(v['base']+32+5*index,v['base']+37+5*index)),terms=[(r.sc.scalar(x,d),[j]) for j,x in enumerate((1,1,1,-1,-256))])
        items.append(('Equality' if index==0 else 'StrictRemainder',i,[[r.sc.scalar(x,d) for x in row] for row in rows]))
    return items


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==7+len(v['ranges']) and type(states) is list and len(states)==2+len(v['ranges']) and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,ts,h,qs,b,rs,d):
    v=derive(p,d);w=witness(p,ts,h,qs,b,rs)
    return dict(quotient_product=qp.prove(v['quotient_product'],qs,b,d),bias=bias.prove(v['bias'],ts,h,d),**{name:r.prove(child,w[name],d) for name,child in v['ranges'].items()})


def assemble(p,pairs,d):
    """Producer only; no child receipt can substitute for its complete proof."""
    v=derive(p,d);names=['quotient_product','bias']+list(v['ranges']);proof={name:pairs[name][0] for name in names};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()}
    t=transcript(v,roots(p,proof)+list(proof['roots'].values()),[pairs[name][1] for name in names],d);proof['zero']=[r.zero_prove(t,i,rows) for _,i,rows in parts(p,proof,d)]
    return proof,t.state


def prove(p,ts,h,qs,b,rs,d):
    return assemble(p,prepare(p,ts,h,qs,b,rs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);names=list(v['ranges']);need(type(expected) is list and len(expected)==7 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'quotient_product','bias','roots','zero'}|set(names) and type(proof['roots']) is dict and set(proof['roots'])==set(names),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()) and type(proof['zero']) is list and len(proof['zero'])==2,'ProofShape');children=[];ranges=[]
    for name,module,offset,label in (('quotient_product',qp,0,'QuotientProduct'),('bias',bias,3,'Bias')):
        try:children.append(module.verify(v[name],expected[offset:offset+3],proof[name],d))
        except ValueError as error:raise ValueError(label+':'+str(error)) from None
    for name,child in v['ranges'].items():
        try:ranges.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    need(r.root(p.remainder,wide_words(v,proof,'remainder'))==expected[6],'Remainder:CommitmentMismatch')
    t=transcript(v,expected+[proof['roots'][name] for name in names],[item['state'] for item in children+ranges],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==2 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==5 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    inherited=[item['account'] for item in children];accounts=[item['account'] for item in ranges]
    return dict(state=t.state,children=children,ranges=ranges,sc=records,claims=claims,draws=dict(t.draws),account=dict(identities=sum((item['identities'] for item in inherited),[])+[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in inherited+accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in inherited+accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
