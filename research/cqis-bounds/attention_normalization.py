"""Draft RFC-0004 A3/A6 / RFC-0009 A2: complete conditional normalization.

Every shared root is passed to each complete child. No wrapper challenge,
plaintext verifier division or additional ownership claim is introduced.
"""
from dataclasses import dataclass
import struct
import attention_global_base as global_base
import attention_sign as raw_sign
import attention_block_total_sign as block_sign
import attention_numerator as numerator
import attention_denominator as denominator
import attention_division as division
import attention_signed_output as signed_output

bounds=numerator.bounds
r=numerator.r
need=r.need
PREFIX=b'stele/research/q26/attention-normalization/v1\0'
ROLES=('offset','base_source','probability','magnitude','sign','numerator','denominator','quotient','product','biased','doubled','remainder','output')
SCALARS=('base_source','probability','denominator','doubled')


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    offset: int
    base_source: int
    probability: int
    magnitude: int
    sign: int
    numerator: int
    denominator: int
    quotient: int
    product: int
    biased: int
    doubled: int
    remainder: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema);s=p.schema;exact=s.accumulation=='exact'
    need(type(p.identity) is int and 0<=p.identity<1<<32 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');base=(1<<63)+(1<<30)*p.identity
    roles=tuple(role for role in ROLES if role!='base_source' or exact);ids=[getattr(p,role) for role in roles]
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<30) for x in ids) and len(set(ids))==len(ids),'Spec')
    need(exact or (type(p.base_source) is int and p.base_source==0),'Spec');children=[]
    if exact:
        children.append(('base',global_base,global_base.Spec(s,4096*p.identity+2,p.probability,p.base_source,p.repetitions),('probability','base_source'),'GlobalBase'))
        shape=raw_sign.bounds.Spec(s.length,s.width,s.fraction,s.exponent,s.value_mode,s.scale,'exact')
        sign=raw_sign.Spec(shape,65536*p.identity+1,p.offset,p.base_source,p.magnitude,p.sign,p.repetitions);children.append(('sign',raw_sign,sign,('offset','base_source','magnitude','sign'),'Sign'))
    else:
        shape=block_sign.bounds.Spec(s.length,s.width,s.fraction,s.exponent,s.value_mode,s.scale,s.drop)
        sign=block_sign.Spec(shape,tuple(range((s.length+1023)//1024)),65536*p.identity+1,p.offset,p.magnitude,p.sign,p.repetitions);children.append(('sign',block_sign,sign,('offset','magnitude','sign'),'Sign'))
    children.extend((
        ('numerator',numerator,numerator.Spec(s,65536*p.identity+2,p.magnitude,p.numerator,p.repetitions),('magnitude','numerator'),'Numerator'),
        ('denominator',denominator,denominator.Spec(s,4096*p.identity+1,p.probability,p.denominator,p.repetitions),('probability','denominator'),'Denominator'),
        ('division',division,division.Spec(s,64*p.identity+1,p.numerator,p.denominator,p.quotient,p.product,p.biased,p.doubled,p.remainder,p.repetitions),('numerator','denominator','quotient','product','biased','doubled','remainder'),'Division'),
        ('output',signed_output,signed_output.Spec(s,65536*p.identity+3,p.sign,p.quotient,p.output,p.repetitions),('sign','quotient','output'),'SignedOutput')))
    for name,module,child,routes,label in children:module.derive(child,d)
    encoded=bounds.encode(s);raw=PREFIX+struct.pack('<BBBQI',1,d,p.repetitions,p.identity,len(encoded))+encoded+b''.join(struct.pack('<Q',getattr(p,role)) for role in ROLES)
    return dict(constants=constants,roles=roles,children=children,n=1<<(s.width-1).bit_length(),base=base,raw=raw)


def witness(p,z,totals):
    """Producer arithmetic only. Verification uses the complete children below."""
    v=derive(p,4);need(type(totals) is list,'Input');bounds.inputs(p.schema,z,tuple(totals));k=v['constants'];exact=p.schema.accumulation=='exact'
    H=z*k['restored_max'] if exact else k['total_max'];offsets=[H+x for x in totals];need(all(0<=x<=2*k['total_max'] for x in offsets),'OffsetRange')
    ms=[abs(x) for x in totals];bs=[int(x<0) for x in totals];us=[x*k['left_factor'] for x in ms];D=z*k['right_factor'];qr=[divmod(2*u+D,2*D) for u in us];qs=[x[0] for x in qr];rs=[x[1] for x in qr];ys=[(1-2*b)*q for b,q in zip(bs,qs)];need(all(-32768<=y<=32767 for y in ys),'OutputRange')
    values=dict(offset=offsets,probability=z,magnitude=ms,sign=bs,numerator=us,denominator=D,quotient=qs,product=[q*D for q in qs],biased=[2*u+D for u in us],doubled=2*D,remainder=rs,output=ys)
    if exact:values['base_source']=H
    return values


def expected_roots(p,z,totals):
    v=derive(p,4);w=witness(p,z,totals);result=[]
    for role in v['roles']:
        width=1 if role=='sign' else 2 if role in ('quotient','output') else 8 if role in ('offset','base_source','probability','magnitude') else 16
        xs=[w[role]] if role in SCALARS else w[role]+[0]*(v['n']-p.schema.width)
        result.append(r.root(getattr(p,role),[x>>(8*k)&255 for k in range(width) for x in xs]))
    return result


def roots(p,proof):
    """Producer consistency check; verify passes expected roots independently."""
    v=derive(p,4);need(type(proof) is dict and set(proof)=={x[0] for x in v['children']},'ProofShape');values={}
    for name,module,child,routes,label in v['children']:
        bound=module.roots(child,proof[name]);need(len(bound)==len(routes),'Root')
        for role,root in zip(routes,bound):
            need(role not in values or values[role]==root,'SourceJoin');values[role]=root
    return [values[role] for role in v['roles']]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==len(v['roles']) and type(states) is list and len(states)==len(v['children']) and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,z,totals,d):
    v=derive(p,d);w=witness(p,z,totals)
    args=dict(sign=(w['offset'],w['base_source']) if p.schema.accumulation=='exact' else (w['offset'],),numerator=(w['magnitude'],),denominator=(z,),division=(w['numerator'],w['denominator'],w['quotient'],w['remainder']),output=(w['sign'],w['output']))
    if p.schema.accumulation=='exact':args['base']=(z,)
    return {name:module.prove(child,*args[name],d) for name,module,child,routes,label in v['children']}


def assemble(p,pairs,d):
    v=derive(p,d);proof={name:pairs[name][0] for name,module,child,routes,label in v['children']}
    return proof,transcript(v,roots(p,proof),[pairs[name][1] for name in proof],d).state


def prove(p,z,totals,d):
    return assemble(p,prepare(p,z,totals,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==len(v['roles']) and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={x[0] for x in v['children']},'ProofShape');bound=dict(zip(v['roles'],expected));children={}
    # Shared sources never come from another child's receipt or the producer.
    for name,module,child,routes,label in v['children']:
        try:children[name]=module.verify(child,[bound[role] for role in routes],proof[name],d)
        except ValueError as error:raise ValueError(label+':'+str(error)) from None
    t=transcript(v,expected,[child['state'] for child in children.values()],d);accounts=[child['account'] for child in children.values()];identities=[]
    for item in accounts:identities.extend(item.get('product_identity_numerators',[]) if 'product_identity_numerator' not in item else [item['product_identity_numerator']])
    return dict(state=t.state,children=children,draws=dict(t.draws),account=dict(identities=sum((x['identities'] for x in accounts),[]),lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),product_identity_numerators=identities,product_reduction_numerator=sum(x.get('product_reduction_numerator',0) for x in accounts),denominator=r.sc.P**d))
