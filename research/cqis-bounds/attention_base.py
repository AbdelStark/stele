"""Draft RFC-0004 A3/A6 / RFC-0009 A2: actual probability sum times fixed S.

Constant-size byte joins retain complete range/product/original consumers.
No native/private admission or proof of upstream source ownership is implied.
"""
from dataclasses import dataclass
import struct
import attention_sum_bounds as bounds
import wide_range as r
import limb_product as lp

need=r.need
PREFIX=b'stele/research/q26/attention-base/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    count: int
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.count) is int and p.count>=1,'Spec');need(p.count<=16384,'Capacity');need(p.count<=constants['term_cap'],'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');base=(1<<63)+(1<<18)*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    zmax=p.count*constants['probability_max'];S=constants['restored_max'];weight_sum=r.Spec(4096*p.identity+1,base+1,(zmax,),p.repetitions);_,bz,_,width,_,_=r.derive(weight_sum,d)
    product=lp.Spec(lp.limbs.Spec(1,zmax,S,8),64*p.identity+1,base+2,base+3,p.repetitions);layout=lp.derive(product,d);need(width<=4 and layout['layout']['planes']>=width and layout['s']<=8,'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQII',1,d,p.repetitions,p.identity,p.source,p.output,p.count,len(encoded))+encoded
    return dict(weight_sum=weight_sum,product=product,layout=layout,zmax=zmax,S=S,hmax=zmax*S,bz=bz,width=width,base=base,raw=raw)


def full_source(v,words):
    r.vector(words,v['width']);return words+[0]*(4-v['width'])


def full_output(v,words):
    r.vector(words,v['layout']['s']);return words+[0]*(8-v['layout']['s'])


def source(v,words):
    r.vector(words,v['width']);return [x for j in range(v['layout']['layout']['planes']) for x in (words[j] if j<v['width'] else 0,v['S']>>(8*j)&255)]


def witness(p,z):
    v=derive(p,4);need(type(z) is int and 0<=z<=v['zmax'],'WeightSum');return lp.limbs.witness(v['product'].schema,(z,),(v['S'],))


def expected_roots(p,z,h):
    v=derive(p,4);need(type(z) is int and 0<=z<=v['zmax'],'WeightSum');need(type(h) is int and 0<=h<=v['hmax'],'Output')
    return [r.root(p.source,list(z.to_bytes(4,'little'))),r.root(p.output,list(h.to_bytes(8,'little')))]


def roots(p,proof):
    v=derive(p,4);return [r.root(p.source,full_source(v,proof['weight_sum']['words'])),r.root(p.output,full_output(v,proof['product']['output']['words']))]


def transcript(v,external,internal,states,d):
    need(type(external) is list and len(external)==2 and type(internal) is list and len(internal)==3 and type(states) is list and len(states)==2 and all(type(x) is bytes and len(x)==32 for x in external+internal+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(external+internal+states),d)


def prepare(p,z,d):
    v=derive(p,d);w=witness(p,z);return dict(weight_sum=r.prove(v['weight_sum'],[z],d),product=lp.prove(v['product'],w,d))


def assemble(p,pairs,d):
    """Producer only; every child is reverified from its expected source in verify."""
    v=derive(p,d);proof={name:pairs[name][0] for name in ('weight_sum','product')};words=proof['weight_sum']['words'];digits=proof['product']['input']['digits']
    internal=[r.source_root(v['weight_sum'],words),lp.ls.source_root(v['layout']['input'],digits),lp.cr.source_root(v['layout']['output'],proof['product']['output']['words'])]
    return proof,transcript(v,roots(p,proof),internal,[pairs[name][1] for name in ('weight_sum','product')],d).state


def prove(p,z,d):
    return assemble(p,prepare(p,z,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');need(type(proof) is dict and set(proof)=={'weight_sum','product'},'ProofShape')
    try:
        part=proof['weight_sum'];need(type(part) is dict and 'words' in part,'ProofShape');words=part['words'];need(r.root(p.source,full_source(v,words))==expected[0],'CommitmentMismatch');compact=r.source_root(v['weight_sum'],words);weight_sum=r.verify(v['weight_sum'],compact,part,d)
    except ValueError as error:raise ValueError('WeightSum:'+str(error)) from None
    actual=source(v,words)
    try:
        part=proof['product'];need(type(part) is dict and type(part.get('input')) is dict and 'digits' in part['input'] and type(part.get('output')) is dict and 'words' in part['output'],'ProofShape')
        lp.ls.source_root(v['layout']['input'],part['input']['digits']);need(part['input']['digits']==actual,'SourceJoin');input_root=lp.ls.source_root(v['layout']['input'],actual);output_root=lp.cr.source_root(v['layout']['output'],part['output']['words']);product=lp.verify(v['product'],[input_root,output_root],part,d)
    except ValueError as error:raise ValueError('Product:'+str(error)) from None
    need(r.root(p.output,full_output(v,part['output']['words']))==expected[1],'Output:CommitmentMismatch');t=transcript(v,expected,[compact,input_root,output_root],[weight_sum['state'],product['state']],d);a,b=weight_sum['account'],product['account']
    return dict(state=t.state,weight_sum=weight_sum,product=product,draws=dict(t.draws),account=dict(identities=[(a['identity_numerator'],a['identity_power'])]+b['identities'],lookup_reduction_numerator=a['lookup_reduction_numerator']+b['lookup_reduction_numerator'],range_reduction_numerator=a['range_reduction_numerator']+b['range_reduction_numerator'],product_identity_numerator=b['product_identity_numerator'],product_reduction_numerator=b['product_reduction_numerator'],denominator=r.sc.P**d))
