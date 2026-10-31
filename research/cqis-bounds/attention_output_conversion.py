"""Draft RFC-0004 A3/A6/A8 / RFC-0009 A2: actual heads to one output row.

Complete normalization precedes assembly of its actual signed-output bytes.
The whole-row converter consumes the derived source root; no wrapper challenge.
"""
from dataclasses import dataclass
import struct
import attention_normalization as norm
import row_code as dynamic
import static_row_code as static

r=norm.r
need=r.need
PREFIX=b'stele/research/q26/attention-output-conversion/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.bounds.Spec
    heads: int
    groups: int
    output_mode: str
    output_scale: int
    identity: int
    sources: tuple
    scale: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.bounds.constants(p.schema)
    need(type(p.heads) is int and type(p.groups) is int and 1<=p.groups<=p.heads<=128 and p.heads%p.groups==0,'Spec')
    count=p.heads*p.schema.width;need(count<=16384,'Capacity')
    need(type(p.identity) is int and 0<=p.identity<1<<24 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.output_mode) is str and p.output_mode in ('dynamic','static'),'Spec')
    row=static.row.Spec('wide',count,p.schema.output_fraction,p.output_mode,p.output_scale);static.row.constants(row)
    need(type(p.sources) is tuple and len(p.sources)==p.heads and all(type(xs) is tuple and len(xs)==len(norm.ROLES) for xs in p.sources),'Spec')
    exact=p.schema.accumulation=='exact';base=(1<<63)+(1<<38)*p.identity;assembled=base+(1<<37)+(1<<26)
    if not exact:need(all(type(xs[1]) is int and xs[1]==0 for xs in p.sources),'Spec')
    external=[x for xs in p.sources for j,x in enumerate(xs) if exact or j!=1]+[p.scale,p.output]
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<38) for x in external) and len(set(external))==len(external),'Spec')
    heads=[norm.Spec(p.schema,256*p.identity+j,*xs,p.repetitions) for j,xs in enumerate(p.sources)]
    for child in heads:norm.derive(child,d)
    module=dynamic if p.output_mode=='dynamic' else static;identity=4096*p.identity+2048 if module is dynamic else 1048576*p.identity+524288
    conversion=module.Spec(row,identity,assembled,p.scale,p.output,p.repetitions);module.derive(conversion,d)
    schema=norm.bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQHHBHQQI',1,d,p.repetitions,p.identity,p.heads,p.groups,int(module is static),p.output_scale,p.scale,p.output,len(schema))+schema
    raw+=b''.join(struct.pack('<Q',x) for xs in p.sources for x in xs)
    return dict(head_specs=heads,module=module,conversion=conversion,roles=tuple(role for role in norm.ROLES if exact or role!='base_source'),base=base,assembled=assembled,count=count,n=1<<(count-1).bit_length(),nh=1<<(p.schema.width-1).bit_length(),raw=raw)


def witness(p,zs,totals):
    v=derive(p,4);need(type(zs) is list and type(totals) is list and len(zs)==len(totals)==p.heads,'Input')
    heads=[norm.witness(child,z,ts) for child,z,ts in zip(v['head_specs'],zs,totals)];wide=[value for head in heads for value in head['output']]
    row=v['module'].witness(v['conversion'],wide)
    return dict(heads=heads,wide=wide,scale=row['scale'] if v['module'] is dynamic else p.output_scale,codes=row['codes'])


def expected_roots(p,zs,totals):
    v=derive(p,4);w=witness(p,zs,totals)
    return dict(heads=[norm.expected_roots(child,z,ts) for child,z,ts in zip(v['head_specs'],zs,totals)],scale=r.root(p.scale,list(w['scale'].to_bytes(2,'little'))),output=r.root(p.output,[x%256 for x in w['codes']]+[0]*(v['n']-v['count'])))


def assembled_words(p,v,proof):
    """Actual child byte views. The verifier calls this only after all head proofs."""
    sources=[head['output']['output']['ranges'][0]['words'] for head in proof['heads']]
    for words in sources:r.vector(words,2*v['nh'])
    result=[]
    for plane in range(2):
        for words in sources:result.extend(words[plane*v['nh']:plane*v['nh']+p.schema.width])
        result.extend([0]*(v['n']-v['count']))
    return result


def proof_shape(p,proof):
    need(type(proof) is dict and set(proof)=={'heads','conversion'} and type(proof['heads']) is list and len(proof['heads'])==p.heads,'ProofShape')


def roots(p,proof):
    """Producer consistency check; verification reconstructs the join independently."""
    v=derive(p,4);proof_shape(p,proof);heads=[norm.roots(child,part) for child,part in zip(v['head_specs'],proof['heads'])]
    row=v['module'].roots(v['conversion'],proof['conversion']);need(row[0]==r.root(v['assembled'],assembled_words(p,v,proof)),'SourceJoin')
    return dict(heads=heads,scale=row[1],output=row[2])


def flatten(v,expected):
    need(type(expected) is dict and set(expected)=={'heads','scale','output'} and type(expected['heads']) is list and len(expected['heads'])==len(v['head_specs']),'Root')
    need(all(type(xs) is list and len(xs)==len(v['roles']) for xs in expected['heads']),'Root')
    values=[root for head in expected['heads'] for root in head]+[expected['scale'],expected['output']];need(all(type(x) is bytes and len(x)==32 for x in values),'Root');return values


def transcript(v,expected,assembled,states,d):
    bound=flatten(v,expected);need(type(assembled) is bytes and len(assembled)==32 and type(states) is list and len(states)==len(v['head_specs'])+1 and all(type(x) is bytes and len(x)==32 for x in states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+[assembled]+states),d)


def prepare(p,zs,totals,d):
    v=derive(p,d);w=witness(p,zs,totals)
    return dict(heads=[norm.prove(child,z,ts,d) for child,z,ts in zip(v['head_specs'],zs,totals)],conversion=v['module'].prove(v['conversion'],w['wide'],d))


def assemble(p,pairs,d):
    v=derive(p,d);proof=dict(heads=[pair[0] for pair in pairs['heads']],conversion=pairs['conversion'][0]);expected=roots(p,proof)
    t=transcript(v,expected,r.root(v['assembled'],assembled_words(p,v,proof)),[pair[1] for pair in pairs['heads']]+[pairs['conversion'][1]],d);return proof,t.state


def prove(p,zs,totals,d):
    return assemble(p,prepare(p,zs,totals,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);flatten(v,expected);proof_shape(p,proof);heads=[]
    for j,(child,bound,part) in enumerate(zip(v['head_specs'],expected['heads'],proof['heads'])):
        try:heads.append(norm.verify(child,bound,part,d))
        except ValueError as error:raise ValueError('Head'+str(j)+':'+str(error)) from None
    # Draft A6 head order: omit each head's padding, then pad the complete row.
    assembled=r.root(v['assembled'],assembled_words(p,v,proof))
    try:row=v['module'].verify(v['conversion'],[assembled,expected['scale'],expected['output']],proof['conversion'],d)
    except ValueError as error:raise ValueError('Conversion:'+str(error)) from None
    t=transcript(v,expected,assembled,[child['state'] for child in heads]+[row['state']],d);hc=[child['account'] for child in heads];rc=row['account'];accounts=hc+[rc]
    return dict(state=t.state,heads=heads,conversion=row,draws=dict(t.draws),account=dict(identities=[identity for x in accounts for identity in x['identities']],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),product_identity_numerators=[loss for x in hc for loss in x['product_identity_numerators']],product_reduction_numerator=sum(x['product_reduction_numerator'] for x in hc),selection_reduction_numerator=rc.get('selection_reduction_numerator',0),denominator=r.sc.P**d))
