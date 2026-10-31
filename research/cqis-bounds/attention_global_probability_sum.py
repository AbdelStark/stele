"""Draft RFC-0004 A3/A6 / RFC-0009 A2: actual eight-byte probability sums.

O(B) byte joins reuse complete source ranges and the limb-product consumer.
No new challenge or whole global field equality; no upstream ownership claim.
"""
from dataclasses import dataclass
import struct
import attention_block_bounds as bounds
import wide_range as r
import limb_product as lp

need=r.need
PREFIX=b'stele/research/q26/attention-global-probability-sum/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    blocks: tuple
    identity: int
    sources: tuple
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.blocks) is tuple and 1<=len(p.blocks)<=constants['block_count_max'] and all(type(x) is int and 0<=x<=constants['block_id_max'] for x in p.blocks) and all(x<y for x,y in zip(p.blocks,p.blocks[1:])),'Spec')
    need(type(p.sources) is tuple and len(p.sources)==len(p.blocks),'Spec');base=(1<<63)+(1<<18)*p.identity;ids=p.sources+(p.output,)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in ids) and len(set(ids))==len(ids),'Spec')
    caps=tuple(min(1024,p.schema.length-1024*block)*constants['probability_max'] for block in p.blocks);source_spec=r.Spec(4096*p.identity+1,base+1,caps,p.repetitions);a,b,n,width,_,_=r.derive(source_spec,d)
    summation=lp.Spec(lp.limbs.Spec(len(p.blocks),max(caps),1,8),64*p.identity+1,base+2,base+3,p.repetitions);layout=lp.derive(summation,d)
    need(width<=4 and layout['layout']['n']==n and layout['layout']['planes']>=width and layout['s']<=8,'Capacity')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQII',1,d,p.repetitions,p.identity,len(p.blocks),len(encoded))+encoded
    raw+=b''.join(struct.pack('<I',block) for block in p.blocks)+b''.join(struct.pack('<Q',identity) for identity in ids)
    return dict(source=source_spec,sum=summation,layout=layout,caps=caps,zmax=sum(caps),a=a,b=b,n=n,width=width,base=base,raw=raw)


def full_source(v,words):
    r.vector(words,v['n']*v['width']);return words+[0]*(v['n']*(4-v['width']))


def full_output(v,words):
    r.vector(words,v['layout']['s']);return words+[0]*(8-len(words))


def source(v,words):
    actual=full_source(v,words);n=v['n']
    # Exact real-block ones remain checked even when every source is zero.
    return [actual[j*n+i] if side==0 else int(j==0 and i<len(v['caps'])) for j in range(v['layout']['layout']['planes']) for side in (0,1) for i in range(n)]


def witness(p,zs):
    v=derive(p,4);need(type(zs) is list and len(zs)==len(v['caps']) and all(type(z) is int and 0<=z<=cap for z,cap in zip(zs,v['caps'])),'Input')
    return lp.limbs.witness(v['sum'].schema,tuple(zs),(1,)*len(zs))


def roots(p,proof):
    v=derive(p,4);words=full_source(v,proof['source']['words'])
    return [r.root(identity,[words[j*v['n']+i] for j in range(4)]) for i,identity in enumerate(p.sources)]+[r.root(p.output,full_output(v,proof['sum']['output']['words']))]


def expected_roots(p,zs):
    witness(p,zs);return [r.root(identity,list(z.to_bytes(4,'little'))) for identity,z in zip(p.sources,zs)]+[r.root(p.output,list(sum(zs).to_bytes(8,'little')))]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==len(v['caps'])+4 and type(states) is list and len(states)==2 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,zs,d):
    v=derive(p,d);w=witness(p,zs);return dict(source=r.prove(v['source'],zs,d),sum=lp.prove(v['sum'],w,d))


def assemble(p,pairs,d):
    """Producer only; every child and exact source join is checked by verify."""
    v=derive(p,d);proof={name:pairs[name][0] for name in ('source','sum')};internal=[r.source_root(v['source'],proof['source']['words']),lp.ls.source_root(v['layout']['input'],proof['sum']['input']['digits']),lp.cr.source_root(v['layout']['output'],proof['sum']['output']['words'])]
    return proof,transcript(v,roots(p,proof)+internal,[pairs[name][1] for name in ('source','sum')],d).state


def prove(p,zs,d):
    return assemble(p,prepare(p,zs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==len(p.blocks)+1 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'source','sum'},'ProofShape')
    try:
        child=proof['source'];need(type(child) is dict and 'words' in child,'ProofShape');words=child['words'];source_root=r.source_root(v['source'],words);source_result=r.verify(v['source'],source_root,child,d)
    except ValueError as error:raise ValueError('Source:'+str(error)) from None
    actual=full_source(v,words)
    for i,(block,identity) in enumerate(zip(p.blocks,p.sources)):need(r.root(identity,[actual[j*v['n']+i] for j in range(4)])==expected[i],'Block:'+str(block)+':CommitmentMismatch')
    try:
        child=proof['sum'];need(type(child) is dict and type(child.get('input')) is dict and 'digits' in child['input'] and type(child.get('output')) is dict and 'words' in child['output'],'ProofShape')
        digits=child['input']['digits'];lp.ls.source_root(v['layout']['input'],digits);need(digits==source(v,words),'SourceJoin');input_root=lp.ls.source_root(v['layout']['input'],digits);output_root=lp.cr.source_root(v['layout']['output'],child['output']['words']);summation=lp.verify(v['sum'],[input_root,output_root],child,d)
    except ValueError as error:raise ValueError('Sum:'+str(error)) from None
    need(r.root(p.output,full_output(v,child['output']['words']))==expected[-1],'Output:CommitmentMismatch');t=transcript(v,expected+[source_root,input_root,output_root],[source_result['state'],summation['state']],d);a,b=source_result['account'],summation['account']
    return dict(state=t.state,source=source_result,sum=summation,draws=dict(t.draws),account=dict(identities=[(a['identity_numerator'],a['identity_power'])]+b['identities'],lookup_reduction_numerator=a['lookup_reduction_numerator']+b['lookup_reduction_numerator'],range_reduction_numerator=a['range_reduction_numerator']+b['range_reduction_numerator'],product_identity_numerator=b['product_identity_numerator'],product_reduction_numerator=b['product_reduction_numerator'],denominator=r.sc.P**d))
