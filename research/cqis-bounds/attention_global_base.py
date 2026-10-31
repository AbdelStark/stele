"""Draft RFC-0004 A3/A6 / RFC-0009 A2: global exact-mode H=S*Z bytes.

One complete scalar limb product plus constant-size byte joins. The external
eight-byte Z must also join the actual positive denominator and global source.
"""
from dataclasses import dataclass
import struct
import attention_normalization_bounds as bounds
import wide_range as r
import limb_product as lp

need=r.need
PREFIX=b'stele/research/q26/attention-global-base/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema);need(p.schema.accumulation=='exact','Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');base=(1<<63)+(1<<18)*p.identity;ids=(p.source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in ids) and len(set(ids))==2,'Spec')
    product=lp.Spec(lp.limbs.Spec(1,constants['z_max'],constants['restored_max'],8),64*p.identity+1,base+1,base+2,p.repetitions);layout=lp.derive(product,d)
    need(layout['layout']['planes']<=8 and layout['s']<=8 and constants['total_max']<1<<50,'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(constants=constants,product=product,layout=layout,base=base,raw=raw)


def source(v,digits):
    r.vector(digits,v['layout']['layout']['cells']);words=digits[::2];return words+[0]*(8-len(words))


def output(v,words):
    r.vector(words,v['layout']['s']);return words+[0]*(8-len(words))


def witness(p,z):
    v=derive(p,4);need(type(z) is int and 0<=z<=v['constants']['z_max'],'WeightSum');return lp.limbs.witness(v['product'].schema,(z,),(v['constants']['restored_max'],))


def roots(p,proof):
    v=derive(p,4);child=proof['product'];return [r.root(p.source,source(v,child['input']['digits'])),r.root(p.output,output(v,child['output']['words']))]


def expected_roots(p,z):
    v=derive(p,4);witness(p,z);return [r.root(p.source,list(z.to_bytes(8,'little'))),r.root(p.output,list((z*v['constants']['restored_max']).to_bytes(8,'little')))]


def transcript(v,bound,state,d):
    need(type(bound) is list and len(bound)==4 and all(type(x) is bytes and len(x)==32 for x in bound) and type(state) is bytes and len(state)==32,'Root');return r.scalar.Transcript(v['raw']+b''.join(bound)+state,d)


def prepare(p,z,d):
    v=derive(p,d);return lp.prove(v['product'],witness(p,z),d)


def assemble(p,pair,d):
    """Producer only; exact S, complete ranges and all originals stay mandatory."""
    v=derive(p,d);child,state=pair;proof={'product':child};internal=[lp.ls.source_root(v['layout']['input'],child['input']['digits']),lp.cr.source_root(v['layout']['output'],child['output']['words'])]
    return proof,transcript(v,roots(p,proof)+internal,state,d).state


def prove(p,z,d):
    return assemble(p,prepare(p,z,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');need(type(proof) is dict and set(proof)=={'product'},'ProofShape')
    try:
        child=proof['product'];need(type(child) is dict and type(child.get('input')) is dict and 'digits' in child['input'] and type(child.get('output')) is dict and 'words' in child['output'],'ProofShape');digits=child['input']['digits']
        input_root=lp.ls.source_root(v['layout']['input'],digits);output_root=lp.cr.source_root(v['layout']['output'],child['output']['words'])
        # Exact factor bytes remain consumed even when the left operand is zero.
        need(digits[1::2]==[v['constants']['restored_max']>>(8*j)&255 for j in range(v['layout']['layout']['planes'])],'Factor');result=lp.verify(v['product'],[input_root,output_root],child,d)
    except ValueError as error:raise ValueError('Product:'+str(error)) from None
    for name,actual,target in zip(('WeightSum','Base'),roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    t=transcript(v,expected+[input_root,output_root],result['state'],d);return dict(state=t.state,product=result,draws=dict(t.draws),account=result['account'])
