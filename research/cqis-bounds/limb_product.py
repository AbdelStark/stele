"""Q26/Q31 consumed unsigned products; Draft RFC-0004 A3, revealing research.

Core arithmetic O(NP+S), plus complete nested ranges/hash work. No digit-pair grid.
"""
from dataclasses import dataclass
import struct
import limb_source as ls

limbs=ls.limbs
cr=ls.r.scalar
sc=cr.sc
need=cr.need
PREFIX=b'stele/research/q26/limb-product/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: limbs.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<50 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+4096*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+4096 for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    input_spec=ls.Spec(p.schema,16*p.identity+1,p.source,p.repetitions); layout=ls.derive(input_spec,d); cert=layout['cert']
    k=len(cert['result_caps']); g=k.bit_length(); size=1<<g
    output=cr.Spec(64*p.identity+16,p.output,cert['result_caps']+(0,)*(size-k),p.repetitions)
    carry=cr.Spec(64*p.identity+17,base,cert['carry_caps']+(0,)*(size-k-1),p.repetitions)
    cr.derive(output,d); cr.derive(carry,d)
    raw=PREFIX+struct.pack('<BBBQQQBI',1,d,p.repetitions,p.identity,p.source,p.output,p.schema.radix_bits,p.schema.count)
    raw+=p.schema.left_max.to_bytes(20,'little')+p.schema.right_max.to_bytes(20,'little')
    return dict(input=input_spec,output=output,carry=carry,layout=layout,cert=cert,k=k,g=g,s=size,
                h=layout['planes'].bit_length()-1,base=base,raw=raw)


def witness(p,w):
    v=derive(p,4)
    need(type(w) is dict and set(w)=={'left','right','result','carry'},'Witness')
    digits=ls.source(v['input'],w['left'],w['right'])
    need(type(w['result']) is tuple and len(w['result'])==v['k'] and type(w['carry']) is tuple and len(w['carry'])==v['k']+1,'Witness')
    z=list(w['result'])+[0]*(v['s']-v['k']); c=list(w['carry'])+[0]*(v['s']-v['k']-1)
    cr.vector(z,v['s']); cr.vector(c,v['s'])
    return digits,z,c


def roots(p,digits,z,c):
    v=derive(p,4)
    return [ls.source_root(v['input'],digits),cr.source_root(v['output'],z),cr.source_root(v['carry'],c)]


def powers(rho,count,d):
    result=[sc.scalar(1,d)]
    for _ in range(1,count): result.append(sc.mul(result[-1],rho))
    return result


def power_mle(rho,point,d):
    """MSB-first MLE of rho^i, without division; RFC-0006 A1 public consumer."""
    value=sc.scalar(1,d); x=rho
    for u in reversed(point):
        value=sc.mul(value,sc.add(sc.add(sc.scalar(1,d),sc.neg(u)),sc.mul(u,x))); x=sc.mul(x,x)
    return value


def mle(values,point,d):
    need(len(values)==1<<len(point),'OpeningShape')
    return cr.zc.total((sc.mul(x,w) for x,w in zip(values,cr.eq_weights(point,d))),d)


def collapse(v,digits,rho,d):
    n,planes=v['layout']['n'],v['layout']['planes']; result=[[sc.scalar(0,d)]*n for _ in range(2)]
    for j,weight in enumerate(powers(rho,planes,d)):
        for side in range(2):
            for i in range(n): result[side][i]=sc.add(result[side][i],sc.mul(weight,sc.scalar(digits[2*n*j+side*n+i],d)))
    return result


def target(p,v,z,c,rho,d):
    # Draft RFC-0004 A3: actual range consumers force columns >=K and C_K to zero.
    return cr.zc.total((sc.mul(weight,sc.scalar(z[k]+(1<<p.schema.radix_bits)*c[k+1]-c[k],d))
                       for k,weight in enumerate(powers(rho,v['k'],d))),d)


def transcript(p,bound,states,d):
    need(type(bound) is list and len(bound)==3 and type(states) is list and len(states)==3 and
         all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return cr.Transcript(derive(p,d)['raw']+b''.join(bound+states),d)


def descriptor(p,v,j,total,d):
    ids=[v['base']+8,v['base']+9] if j==0 else [v['base']+10,v['base']+10+j]
    return dict(id=256*p.identity+128+j,m=v['layout']['a'] if j==0 else v['h'],ids=ids,
                terms=[(sc.scalar(1,d),[0,1])],sum=total)


def core_prove(p,bound,states,digits,z,c,d):
    """Arithmetic producer; full verify authenticates its originals and ranges."""
    v=derive(p,d); cr.vector(digits,v['layout']['cells']); cr.vector(z,v['s']); cr.vector(c,v['s'])
    t=transcript(p,bound,states,d); rho=sc.challenge(t)
    main,point=sc.prove(t,descriptor(p,v,0,target(p,v,z,c,rho,d),d),collapse(v,digits,rho,d))
    proof=dict(main=main); n=v['layout']['n']; weights=powers(rho,v['layout']['planes'],d)
    for side,name in enumerate(('left','right')):
        folded=[cr.zc.folded([sc.scalar(x,d) for x in digits[2*n*j+side*n:2*n*j+(side+1)*n]],point) for j in range(v['layout']['planes'])]
        proof[name],_=sc.prove(t,descriptor(p,v,side+1,main['final'][side],d),[weights,folded])
    return proof,t.state


def shape(proof,dimensions,d):
    need(type(proof) is dict and set(proof)=={'main','left','right'},'ProofShape')
    for name,m in zip(('main','left','right'),dimensions):
        part=proof[name]
        need(type(part) is dict and set(part)=={'rounds','final'} and type(part['rounds']) is list and len(part['rounds'])==m and
             all(type(row) is list and len(row)==3 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==2,'ProofShape')
        cr.lu.ft.fields(sum(part['rounds'],[])+part['final'],d)


def core_verify(p,bound,states,digits,z,c,proof,d):
    """Conditional core on authenticated, range-checked originals; full acceptance is verify."""
    v=derive(p,d); shape(proof,(v['layout']['a'],v['h'],v['h']),d)
    t=transcript(p,bound,states,d); rho=sc.challenge(t)
    try: main=sc.verify_reduction(t,descriptor(p,v,0,target(p,v,z,c,rho,d),d),proof['main'])
    except ValueError as error: raise ValueError('Product:'+str(error)) from None
    originals=[sc.scalar(x,d) for x in digits]; sources=[]; claims=[]; public=[]
    for side,name in enumerate(('left','right')):
        try:
            receipt=sc.verify_reduction(t,descriptor(p,v,side+1,main['claims'][side][1],d),proof[name])
            need(power_mle(rho,receipt['point'],d)==receipt['claims'][0][1],'PowerClaimMismatch')
            point=receipt['point']+[sc.scalar(side,d)]+main['point']; value=receipt['claims'][1][1]
            need(mle(originals,point,d)==value,'SourceClaimMismatch')
        except ValueError as error: raise ValueError(name.title()+'Source:'+str(error)) from None
        sources.append(receipt); claims.append((p.source,point,value)); public.append((receipt['claims'][0][0],receipt['point'],receipt['claims'][0][1]))
    return dict(state=t.state,rho=rho,main=main,sources=sources,original_claims=claims,public_claims=public,
                draws=dict(t.draws),sc=[main['sc']]+[x['sc'] for x in sources])


def ranges(p,w,d):
    v=derive(p,d); digits,z,c=witness(p,w)
    return [ls.prove(v['input'],digits,d),cr.prove(v['output'],z,d),cr.prove(v['carry'],c,d)]


def assemble(p,pairs,d):
    digits,z,c=pairs[0][0]['digits'],pairs[1][0]['words'],pairs[2][0]['words']; bound=roots(p,digits,z,c)
    core,state=core_prove(p,bound,[pair[1] for pair in pairs],digits,z,c,d)
    return dict(input=pairs[0][0],output=pairs[1][0],carry=pairs[2][0],carry_root=bound[2],core=core),state


def prove(p,w,d):
    return assemble(p,ranges(p,w,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'input','output','carry','carry_root','core'},'ProofShape')
    need(type(proof['carry_root']) is bytes and len(proof['carry_root'])==32,'Root')
    bound=expected+[proof['carry_root']]; children=[]
    for name,root,verifier in zip(('input','output','carry'),bound,(ls.verify,cr.verify,cr.verify)):
        try: children.append(verifier(v[name],root,proof[name],d))
        except ValueError as error: raise ValueError(name.title()+':'+str(error)) from None
    core=core_verify(p,bound,[x['state'] for x in children],proof['input']['digits'],proof['output']['words'],proof['carry']['words'],proof['core'],d)
    a,b,c=[x['account'] for x in children]
    return dict(state=core['state'],input=children[0],output=children[1],carry=children[2],core=core,
                account=dict(identities=a['identities']+[(x['identity_numerator'],x['identity_power']) for x in (b,c)],
                    lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in (a,b,c)),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in (a,b,c)),
                    product_identity_numerator=v['k']-1,product_reduction_numerator=sum(x['numerator'] for x in core['sc']),denominator=sc.P**d))
