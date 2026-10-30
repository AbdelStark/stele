"""Q26/Q31 Requant consumers: RFC-0004 A1 / Draft A3, full-reveal research.

Work is the sum of fixed signed/range/product consumers plus linear byte routing.
"""
from dataclasses import dataclass
import struct
import requant as req
import signed_source as ss
import limb_product as lp

r=ss.r
need=r.need
ROLES=('product','bias','quotient_product','division')
PREFIX=b'stele/research/q26/requant-consumer/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: req.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(p.schema) is req.Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<42 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<20)*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<20) for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    cert=req.derive(p.schema); schemas=req.column_specs(p.schema)
    inp=ss.Spec(2048*p.identity+1,p.source,base+1,32,1,p.repetitions)
    out=ss.Spec(2048*p.identity+2,p.output,base+2,p.schema.bits,1,p.repetitions)
    rem=r.Spec(16384*p.identity+32,base+3,(cert['divisor']-1,),p.repetitions)
    products={name:lp.Spec(schemas[name],256*p.identity+16+j,base+16+2*j,base+17+2*j,p.repetitions) for j,name in enumerate(ROLES)}
    ss.derive(inp,d); ss.derive(out,d); r.derive(rem,d)
    for child in products.values(): lp.derive(child,d)
    raw=PREFIX+struct.pack('<BBBQQQHBB',1,d,p.repetitions,p.identity,p.source,p.output,p.schema.mantissa,p.schema.shift,p.schema.bits)
    return dict(input=inp,output=out,remainder=rem,products=products,cert=cert,base=base,raw=raw)


def word(value):
    need(type(value) is int and value>=0,'SourceValue')
    return list(value.to_bytes(max(1,(value.bit_length()+7)//8),'little'))


def operand_root(child,left,right):
    """Exact original byte layout; preserve high source bytes even for zero caps."""
    v=lp.derive(child,4); n=v['layout']['n']; planes=v['layout']['planes']; count=child.schema.count
    need(child.schema.radix_bits==8 and all(type(rows) is list and len(rows)==count for rows in (left,right)),'SourceShape')
    for xs in left+right:
        need(type(xs) is list and bool(xs),'SourceShape'); r.vector(xs,len(xs))
        need(all(x<256 for x in xs),'SourceByte'); need(not any(xs[planes:]),'SourceWidth')
    digits=[]
    for j in range(planes):
        for rows in (left,right):
            digits.extend(xs[j] if j<len(xs) else 0 for xs in rows); digits.extend([0]*(n-count))
    return lp.ls.source_root(v['input'],digits)


def opened(part):
    need(type(part) is dict and type(part.get('words')) is list,'ProofShape')
    return part['words']


def signed_words(part,index):
    need(type(part) is dict and type(part.get('ranges')) is list and len(part['ranges'])==3,'ProofShape')
    return opened(part['ranges'][index])


def product_words(part):
    need(type(part) is dict and 'output' in part,'ProofShape')
    return opened(part['output'])


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(ss.derive(v[name],4)['ranges'][0],signed_words(proof[name],0)) for name in ('input','output')]


def bindings(p,v,proof,expected,d):
    """Derive expected shared-source roots; every referenced proof is still verified."""
    mags=[signed_words(proof[name],1) for name in ('input','output')]; rem=opened(proof['remainder'])
    bounds=expected+[r.source_root(ss.derive(v[name],d)['ranges'][1],xs) for name,xs in zip(('input','output'),mags)]
    bounds.append(r.source_root(v['remainder'],rem)); prods=proof['products']; c=v['cert']
    values=dict(product=([mags[0]],[word(p.schema.mantissa)]),
                bias=([product_words(prods['product']),word(c['bias'])],[word(1),word(1)]),
                quotient_product=([mags[1]],[word(c['divisor'])]),
                division=([product_words(prods['quotient_product']),rem],[word(1),word(1)]))
    targets={}
    for name,child in v['products'].items():
        target=[operand_root(child,*values[name]),lp.cr.source_root(lp.derive(child,d)['output'],product_words(prods[name]))]
        targets[name]=target; bounds.extend(target)
    return bounds,targets


def sign_instance(p,v,proof,d):
    width=p.schema.bits//8; signs=[signed_words(proof[name],2) for name in ('input','output')]
    for xs in signs: r.vector(xs,2)
    mag=signed_words(proof['output'],1); r.vector(mag,width)
    rows=[[r.sc.scalar(xs[0],d)]*width for xs in signs]+[[r.sc.scalar(x,d) for x in mag]]
    return dict(id=(1<<20)*p.identity+900000,m=width.bit_length()-1,k=0,ids=[v['base']+32,v['base']+33,v['base']+2],
                terms=[(r.sc.scalar(1,d),[0,2]),(r.sc.scalar(-1,d),[1,2])]),rows


def transcript(p,bounds,states,d):
    need(type(bounds) is list and len(bounds)==13 and type(states) is list and len(states)==7 and
         all(type(x) is bytes and len(x)==32 for x in bounds+states),'Root')
    return r.scalar.Transcript(derive(p,d)['raw']+b''.join(bounds+states),d)


def prepare(p,acc,d):
    v=derive(p,d); w=req.witness(p.schema,acc)
    return dict(input=ss.prove(v['input'],[acc],d),output=ss.prove(v['output'],[w['output']],d),
                remainder=r.prove(v['remainder'],[w['remainder']],d),
                products={name:lp.prove(child,w['columns'][name],d) for name,child in v['products'].items()})


def assemble(p,pairs,d):
    """Arithmetic composition producer; only verify authenticates every relationship."""
    v=derive(p,d); proof={name:pairs[name][0] for name in ('input','output','remainder')}
    proof['products']={name:pairs['products'][name][0] for name in ROLES}
    states=[pairs[name][1] for name in ('input','output','remainder')]+[pairs['products'][name][1] for name in ROLES]
    bounds,_=bindings(p,v,proof,roots(p,proof),d); t=transcript(p,bounds,states,d)
    i,tables=sign_instance(p,v,proof,d); proof['sign']=r.zero_prove(t,i,tables)
    return proof,t.state


def prove(p,acc,d):
    return assemble(p,prepare(p,acc,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'input','output','remainder','products','sign'} and
         type(proof['products']) is dict and set(proof['products'])==set(ROLES),'ProofShape')
    bounds,targets=bindings(p,v,proof,expected,d); children=[]
    for name,target,verify_child in (('input',[expected[0],bounds[2]],ss.verify),
                                    ('output',[expected[1],bounds[3]],ss.verify),('remainder',bounds[4],r.verify)):
        try: children.append(verify_child(v[name],target,proof[name],d))
        except ValueError as error: raise ValueError(name.title()+':'+str(error)) from None
    products=[]
    for name,child in v['products'].items():
        try: products.append(lp.verify(child,targets[name],proof['products'][name],d))
        except ValueError as error: raise ValueError(name.title().replace('_','')+':'+str(error)) from None
    # Authenticated byte equality, with fixed zero extension; no field alias.
    left=product_words(proof['products']['bias']); right=product_words(proof['products']['division'])
    width=max(len(left),len(right)); need(left+[0]*(width-len(left))==right+[0]*(width-len(right)),'ResultJoin')
    i,tables=sign_instance(p,v,proof,d); part=proof['sign']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
         and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==3 for row in part['rounds'])
         and type(part['final']) is list and len(part['final'])==3 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    t=transcript(p,bounds,[x['state'] for x in children+products],d)
    try: sign,_=r.zc.verify(t,i,part,tables)
    except ValueError as error: raise ValueError('SignTransfer:'+str(error)) from None
    rem=children[2]['account']; accounts=[x['account'] for x in children+products]
    identities=children[0]['account']['identities']+children[1]['account']['identities']+[(rem['identity_numerator'],rem['identity_power'])]
    for child in products: identities.extend(child['account']['identities'])
    return dict(state=t.state,children=children,products=products,sign=sign,draws=dict(t.draws),
                account=dict(identities=identities,lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in sign['sc']),
                    product_identity_numerator=sum(x['account']['product_identity_numerator'] for x in products),
                    product_reduction_numerator=sum(x['account']['product_reduction_numerator'] for x in products),denominator=r.sc.P**d))
