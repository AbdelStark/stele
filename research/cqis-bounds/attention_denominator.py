"""Draft RFC-0004 A3/A6 / RFC-0009 A2: positive scaled attention denominators.

Constant-size byte joins retain a complete gap range and two limb products.
No whole-field global equality, new challenge or upstream ownership claim.
"""
from dataclasses import dataclass
import struct
import attention_normalization_bounds as bounds
import wide_range as r
import limb_product as lp

need=r.need
PREFIX=b'stele/research/q26/attention-denominator/v1\0'
ROLES=('positive','denominator')


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
    gap_max=constants['z_max']-constants['z_min'];gap=r.Spec(4096*p.identity+1,base+1,(gap_max,),p.repetitions);_,bg,_,width,_,_=r.derive(gap,d)
    positive=lp.Spec(lp.limbs.Spec(2,max(gap_max,constants['z_min']),1,8),64*p.identity+1,base+2,base+3,p.repetitions)
    denominator=lp.Spec(bounds.column_specs(p.schema)['shared_columns']['denominator'],64*p.identity+2,base+4,base+5,p.repetitions);layouts={role:lp.derive(child,d) for role,child in zip(ROLES,(positive,denominator))}
    need(width<=layouts['positive']['layout']['planes']<=8 and layouts['positive']['s']<=8 and layouts['denominator']['layout']['planes']<=8 and layouts['denominator']['s']<=16,'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(constants=constants,gap=gap,positive=positive,denominator=denominator,layouts=layouts,bg=bg,width=width,base=base,raw=raw)


def full_sum(v,words):
    r.vector(words,v['layouts']['positive']['s']);return words+[0]*(8-len(words))


def full_output(v,words):
    r.vector(words,v['layouts']['denominator']['s']);return words+[0]*(16-len(words))


def positive_source(v,words):
    r.vector(words,v['width']);Q=v['constants']['z_min']
    return [x for j in range(v['layouts']['positive']['layout']['planes']) for x in (words[j] if j<len(words) else 0,Q>>(8*j)&255,int(j==0),int(j==0))]


def denominator_source(v,words):
    actual=full_sum(v,words);planes=v['layouts']['denominator']['layout']['planes'];need(not any(actual[planes:]),'SourcePadding');F=v['constants']['right_factor']
    return [x for j in range(planes) for x in (actual[j],F>>(8*j)&255)]


def witness(p,z):
    v=derive(p,4);Q=v['constants']['z_min'];need(type(z) is int and Q<=z<=v['constants']['z_max'],'WeightSum')
    return dict(gap=[z-Q],positive=lp.limbs.witness(v['positive'].schema,(z-Q,Q),(1,1)),denominator=lp.limbs.witness(v['denominator'].schema,(z,),(v['constants']['right_factor'],)))


def roots(p,proof):
    v=derive(p,4);return [r.root(p.source,full_sum(v,proof['positive']['output']['words'])),r.root(p.output,full_output(v,proof['denominator']['output']['words']))]


def expected_roots(p,z):
    v=derive(p,4);witness(p,z);return [r.root(p.source,list(z.to_bytes(8,'little'))),r.root(p.output,list((z*v['constants']['right_factor']).to_bytes(16,'little')))]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==7 and type(states) is list and len(states)==3 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,z,d):
    v=derive(p,d);w=witness(p,z);return dict(gap=r.prove(v['gap'],w['gap'],d),**{role:lp.prove(v[role],w[role],d) for role in ROLES})


def assemble(p,pairs,d):
    """Producer only; every child, original and exact byte join remains mandatory."""
    v=derive(p,d);proof={role:pairs[role][0] for role in ('gap',)+ROLES};internal=[r.source_root(v['gap'],proof['gap']['words'])]
    for role in ROLES:internal.extend((lp.ls.source_root(v['layouts'][role]['input'],proof[role]['input']['digits']),lp.cr.source_root(v['layouts'][role]['output'],proof[role]['output']['words'])))
    return proof,transcript(v,roots(p,proof)+internal,[pairs[role][1] for role in ('gap',)+ROLES],d).state


def prove(p,z,d):
    return assemble(p,prepare(p,z,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');need(type(proof) is dict and set(proof)=={'gap','positive','denominator'},'ProofShape')
    try:
        child=proof['gap'];need(type(child) is dict and 'words' in child,'ProofShape');words=child['words'];gap_root=r.source_root(v['gap'],words);gap=r.verify(v['gap'],gap_root,child,d)
    except ValueError as error:raise ValueError('Gap:'+str(error)) from None
    def check(role,actual):
        try:
            child=proof[role];need(type(child) is dict and type(child.get('input')) is dict and 'digits' in child['input'] and type(child.get('output')) is dict and 'words' in child['output'],'ProofShape')
            digits=child['input']['digits'];input_root=lp.ls.source_root(v['layouts'][role]['input'],digits);need(digits==actual,'SourceJoin');output_root=lp.cr.source_root(v['layouts'][role]['output'],child['output']['words']);result=lp.verify(v[role],[input_root,output_root],child,d)
            return result,[input_root,output_root]
        except ValueError as error:raise ValueError(role.title()+':'+str(error)) from None
    positive,pos_roots=check('positive',positive_source(v,words));need(r.root(p.source,full_sum(v,proof['positive']['output']['words']))==expected[0],'WeightSum:CommitmentMismatch')
    denominator,den_roots=check('denominator',denominator_source(v,proof['positive']['output']['words']));need(r.root(p.output,full_output(v,proof['denominator']['output']['words']))==expected[1],'Denominator:CommitmentMismatch')
    t=transcript(v,expected+[gap_root]+pos_roots+den_roots,[child['state'] for child in (gap,positive,denominator)],d);a,b,c=(child['account'] for child in (gap,positive,denominator))
    return dict(state=t.state,gap=gap,positive=positive,denominator=denominator,draws=dict(t.draws),account=dict(identities=[(a['identity_numerator'],a['identity_power'])]+b['identities']+c['identities'],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in (a,b,c)),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in (a,b,c)),product_identity_numerators=[x['product_identity_numerator'] for x in (b,c)],product_reduction_numerator=b['product_reduction_numerator']+c['product_reduction_numerator'],denominator=r.sc.P**d))
