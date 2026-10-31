"""Draft RFC-0004 A3/A6 / RFC-0009 A2: complete doubled denominator bytes.

One scalar limb product retains every range, operand and public-power claim.
Positivity requires composition with the actual positive denominator source.
"""
from dataclasses import dataclass
import struct
import attention_normalization_bounds as bounds
import wide_range as r
import limb_product as lp

need=r.need
PREFIX=b'stele/research/q26/attention-doubled-denominator/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');base=(1<<63)+(1<<18)*p.identity;ids=(p.source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in ids) and len(set(ids))==2,'Spec')
    double=lp.Spec(bounds.column_specs(p.schema)['shared_columns']['doubled_denominator'],64*p.identity+1,base+1,base+2,p.repetitions);layout=lp.derive(double,d)
    need(layout['layout']['planes']<=16 and layout['s']<=16 and constants['double_denominator_max']<1<<128,'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(constants=constants,double=double,layout=layout,base=base,raw=raw)


def source(v,digits):
    r.vector(digits,v['layout']['layout']['cells']);words=digits[::2];return words+[0]*(16-len(words))


def output(v,words):
    r.vector(words,v['layout']['s']);return words+[0]*(16-len(words))


def witness(p,D):
    v=derive(p,4);need(type(D) is int and 0<=D<=v['constants']['denominator_max'],'Denominator');return lp.limbs.witness(v['double'].schema,(D,),(2,))


def roots(p,proof):
    v=derive(p,4);child=proof['double'];return [r.root(p.source,source(v,child['input']['digits'])),r.root(p.output,output(v,child['output']['words']))]


def expected_roots(p,D):
    derive(p,4);witness(p,D);return [r.root(p.source,list(D.to_bytes(16,'little'))),r.root(p.output,list((2*D).to_bytes(16,'little')))]


def transcript(v,bound,state,d):
    need(type(bound) is list and len(bound)==4 and all(type(x) is bytes and len(x)==32 for x in bound) and type(state) is bytes and len(state)==32,'Root');return r.scalar.Transcript(v['raw']+b''.join(bound)+state,d)


def prepare(p,D,d):
    v=derive(p,d);return lp.prove(v['double'],witness(p,D),d)


def assemble(p,pair,d):
    """Producer only; exact factor, complete ranges and originals remain mandatory."""
    v=derive(p,d);child,state=pair;proof={'double':child};internal=[lp.ls.source_root(v['layout']['input'],child['input']['digits']),lp.cr.source_root(v['layout']['output'],child['output']['words'])]
    return proof,transcript(v,roots(p,proof)+internal,state,d).state


def prove(p,D,d):
    return assemble(p,prepare(p,D,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');need(type(proof) is dict and set(proof)=={'double'},'ProofShape')
    try:
        child=proof['double'];need(type(child) is dict and type(child.get('input')) is dict and 'digits' in child['input'] and type(child.get('output')) is dict and 'words' in child['output'],'ProofShape');digits=child['input']['digits']
        input_root=lp.ls.source_root(v['layout']['input'],digits);output_root=lp.cr.source_root(v['layout']['output'],child['output']['words']);need(digits[1::2]==[2]+[0]*(v['layout']['layout']['planes']-1),'Factor');result=lp.verify(v['double'],[input_root,output_root],child,d)
    except ValueError as error:raise ValueError('Double:'+str(error)) from None
    for name,actual,target in zip(('Denominator','Doubled'),roots(p,proof),expected):need(actual==target,name+':CommitmentMismatch')
    t=transcript(v,expected+[input_root,output_root],result['state'],d);return dict(state=t.state,double=result,draws=dict(t.draws),account=result['account'])
