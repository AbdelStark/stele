"""Draft RFC-0004 A3/A6 / RFC-0009 A2: canonical signed attention outputs.

Complete Boolean input-sign and int16 signed-source proofs precede one A3.
Actual canonical sign/magnitude/division provenance must join these roots.
"""
from dataclasses import dataclass
import struct
import attention_normalization_bounds as bounds
import signed_source as signed

r=signed.r
need=r.need
PREFIX=b'stele/research/q26/attention-signed-output/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    sign: int
    quotient: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');a=(p.schema.width-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=(p.sign,p.quotient,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==3,'Spec')
    sign=r.Spec(256*p.identity+1,p.sign,(1,)*p.schema.width,p.repetitions);output=signed.Spec(32*p.identity+1,p.output,p.quotient,16,p.schema.width,p.repetitions);r.derive(sign,d);signed.derive(output,d);need(2*32768<r.sc.P,'FieldBound')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQQI',1,d,p.repetitions,p.identity,*ids,len(encoded))+encoded
    return dict(sign=sign,output=output,a=a,n=n,base=base,raw=raw)


def inputs(p,bs,ys):
    derive(p,4);need(type(bs) is list and type(ys) is list and len(bs)==len(ys)==p.schema.width and all(type(b) is int and b in (0,1) for b in bs) and all(type(y) is int and -32768<=y<=32767 for y in ys),'Input')


def roots(p,proof):
    v=derive(p,4);sv=signed.derive(v['output'],4)
    return [r.source_root(v['sign'],proof['sign']['words']),r.source_root(sv['ranges'][1],proof['output']['ranges'][1]['words']),r.source_root(sv['ranges'][0],proof['output']['ranges'][0]['words'])]


def expected_roots(p,bs,ys):
    v=derive(p,4);inputs(p,bs,ys);sv=signed.derive(v['output'],4);raw,mag,_,_=signed.witness(v['output'],ys)
    return [r.source_root(child,r.witness(child,values)[0]) for child,values in ((v['sign'],bs),(sv['ranges'][1],mag),(sv['ranges'][0],raw))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];mag=proof['output']['ranges'][1]['words'];bs=proof['sign']['words'];flags=proof['output']['ranges'][2]['words']
    for words,size in ((mag,2*n),(bs,n),(flags,2*n)):r.vector(words,size)
    # Draft A6: both actual magnitude bytes reconstruct q<=32768. q=0
    # permits a negative input rounded to zero without dropping any consumer.
    rows=([mag[i]+256*mag[n+i] for i in range(n)],bs,flags[:n]);i=dict(id=1024*p.identity+128,m=v['a'],k=0,ids=[v['base']+j for j in range(16,19)],terms=[(r.sc.scalar(1,d),[0,1]),(r.sc.scalar(-1,d),[0,2])])
    return i,[[r.sc.scalar(x,d) for x in row] for row in rows]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==3 and type(states) is list and len(states)==2 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root');return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,bs,ys,d):
    v=derive(p,d);inputs(p,bs,ys);return dict(sign=r.prove(v['sign'],bs,d),output=signed.prove(v['output'],ys,d))


def assemble(p,pairs,d):
    """Producer only; both complete children remain mandatory at zero output."""
    v=derive(p,d);proof={name:pairs[name][0] for name in ('sign','output')};t=transcript(v,roots(p,proof),[pairs[name][1] for name in ('sign','output')],d);proof['zero']=r.zero_prove(t,*parts(p,proof,d));return proof,t.state


def prove(p,bs,ys,d):
    return assemble(p,prepare(p,bs,ys,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');need(type(proof) is dict and set(proof)=={'sign','output','zero'},'ProofShape')
    try:sign=r.verify(v['sign'],expected[0],proof['sign'],d)
    except ValueError as error:raise ValueError('Sign:'+str(error)) from None
    try:output=signed.verify(v['output'],[expected[2],expected[1]],proof['output'],d)
    except ValueError as error:raise ValueError('Output:'+str(error)) from None
    i,tables=parts(p,proof,d);part=proof['zero'];need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==3 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==3 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField');t=transcript(v,expected,[sign['state'],output['state']],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('SignedOutput:'+str(error)) from None
    sa,oa=sign['account'],output['account'];records=receipt['sc'];return dict(state=t.state,children=[sign,output],sc=records,claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(sa['identity_numerator'],sa['identity_power'])]+oa['identities'],lookup_reduction_numerator=sa['lookup_reduction_numerator']+oa['lookup_reduction_numerator'],range_reduction_numerator=sa['range_reduction_numerator']+oa['range_reduction_numerator']+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
