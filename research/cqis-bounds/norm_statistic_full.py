"""RFC-0022 §§2.1,2.3,5: full statistic consumer under Draft RFC-0004 A3.

O(N) producer/views; independent revealing A1 originals cost O(N log N).
Inherited signed/range/hash work remains; no native/private norm admission.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import signed_source as ss
import function_identity as fn

r=ss.r
need=r.need
PREFIX=b'stele/research/q26/norm-statistic-full/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    constants=norm.constants(p.schema);column=norm.column_specs(p.schema)['statistic'];cert=norm.limbs.derive(column)
    base=(1<<63)+(1<<18)*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    signed=ss.Spec(512*p.identity+1,p.source,base+1,16,p.schema.d,p.repetitions);layout=ss.derive(signed,d)
    output=r.Spec(4096*p.identity+65,base+2,(constants['S_max'],),p.repetitions)
    carry=r.Spec(4096*p.identity+66,base+3,cert['carry_caps'],p.repetitions)
    _,bs,_,ws,_,_=r.derive(output,d);ac,bc,nc,wc,_,_=r.derive(carry,d)
    need(bs in (2,3) and ac==3 and nc==8 and bc<=2,'Capacity')
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQ',1,d,p.repetitions,p.identity,p.source,p.output)+fn.encode(function)
    return dict(signed=signed,output=output,carry=carry,column=column,cert=cert,constants=constants,
                a=layout['a'],n=layout['n'],base=base,bs=bs,bc=bc,ws=ws,wc=wc,raw=raw)


def witness(p,xs):
    v=derive(p,4);magnitude=tuple(ss.witness(v['signed'],xs)[1]);w=norm.limbs.witness(v['column'],magnitude,magnitude)
    return dict(output=[sum(x*x for x in xs)],carry=list(w['carry']))


def full_output(v,words):
    r.vector(words,v['ws']);return words+[0]*(8-v['ws'])


def expected_roots(p,xs,statistic):
    v=derive(p,4);raw=ss.witness(v['signed'],xs)[0];child=ss.derive(v['signed'],4)['ranges'][0]
    need(type(statistic) is int and 0<=statistic<=v['constants']['S_max'],'Statistic')
    return [r.source_root(child,r.witness(child,raw)[0]),r.root(p.output,list(norm.limbs.digits(statistic,8,8)))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];mag=proof['source']['ranges'][1]['words'];r.vector(mag,2*n)
    output=full_output(v,proof['output']['words']);words=proof['carry']['words'];r.vector(words,8*v['wc'])
    carries=[sum(words[8*j+i]<<(8*j) for j in range(v['wc'])) for i in range(8)]+[0]
    lo,hi=[[r.sc.scalar(x,d) for x in row] for row in (mag[:n],mag[n:])]
    definitions=[([v['base']+16],[lo],[(1,[0,0])]),
                 ([v['base']+16,v['base']+17],[lo,hi],[(2,[0,1])]),
                 ([v['base']+17],[hi],[(1,[0,0])])]
    for k in range(8):
        ids,tables,terms=definitions[k] if k<3 else ([],[],[])
        yield dict(id=16384*p.identity+512+k,m=v['a'] if k<3 else 0,ids=ids,
                   terms=[(r.sc.scalar(c,d),indices) for c,indices in terms],
                   sum=r.sc.scalar(output[k]+256*carries[k+1]-carries[k],d)),tables


def transcript(v,roots,states,d):
    need(type(roots) is list and len(roots)==5 and type(states) is list and len(states)==3 and
         all(type(x) is bytes and len(x)==32 for x in roots+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots+states),d)


def prepare(p,xs,d):
    v=derive(p,d);w=witness(p,xs)
    return dict(source=ss.prove(v['signed'],xs,d),output=r.prove(v['output'],w['output'],d),carry=r.prove(v['carry'],w['carry'],d))


def assemble(p,pairs,d):
    """Producer for supplied child proofs; only complete verify grants acceptance."""
    v=derive(p,d);proof={name:pairs[name][0] for name in ('source','output','carry')}
    proof['magnitude_root']=r.root(v['base']+1,proof['source']['ranges'][1]['words'])
    for name in ('output','carry'):proof[name+'_root']=r.source_root(v[name],proof[name]['words'])
    roots=[r.source_root(ss.derive(v['signed'],d)['ranges'][0],proof['source']['ranges'][0]['words']),
           r.root(p.output,full_output(v,proof['output']['words']))]+[proof[name+'_root'] for name in ('magnitude','output','carry')]
    t=transcript(v,roots,[pairs[name][1] for name in ('source','output','carry')],d)
    proof['columns']=[r.sc.prove(t,i,tables)[0] for i,tables in parts(p,proof,d)]
    return proof,t.state


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'source','output','carry','magnitude_root','output_root','carry_root','columns'},'ProofShape')
    need(all(type(proof[k+'_root']) is bytes and len(proof[k+'_root'])==32 for k in ('magnitude','output','carry')),'Root')
    need(type(proof['columns']) is list and len(proof['columns'])==8,'ProofShape')
    try:signed=ss.verify(v['signed'],[expected[0],proof['magnitude_root']],proof['source'],d)
    except ValueError as error:raise ValueError('Source:'+str(error)) from None
    ranges=[]
    for name in ('output','carry'):
        try:ranges.append(r.verify(v[name],proof[name+'_root'],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    need(r.root(p.output,full_output(v,proof['output']['words']))==expected[1],'Output:CommitmentMismatch')
    roots=expected+[proof[k+'_root'] for k in ('magnitude','output','carry')]
    t=transcript(v,roots,[signed['state']]+[x['state'] for x in ranges],d);records=[];claims=[]
    for k,((i,tables),part) in enumerate(zip(parts(p,proof,d),proof['columns'])):
        try:
            need(type(part) is dict and set(part)=={'rounds','final'} and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
                 all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and
                 type(part['final']) is list and len(part['final'])==len(i['ids']),'ProofShape')
            need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value)
                     for row in part['rounds']+[part['final']] for value in row),'NoncanonicalField')
            # Every original view, including a zero-hidden factor, has its own
            # independent full-hypercube consumer at the A1-emitted point.
            receipt=r.sc.verify_public(t,i,part,tables)
        except ValueError as error:raise ValueError('Column'+str(k)+':'+str(error)) from None
        records.append(receipt['sc']);claims.extend(receipt['claims'])
    a=signed['account'];others=[x['account'] for x in ranges]
    return dict(state=t.state,signed=signed,ranges=ranges,sc=records,claims=claims,draws=dict(t.draws),
        account=dict(identities=a['identities']+[(x['identity_numerator'],x['identity_power']) for x in others],
            lookup_reduction_numerator=a['lookup_reduction_numerator']+sum(x['lookup_reduction_numerator'] for x in others),
            range_reduction_numerator=a['range_reduction_numerator']+sum(x['range_reduction_numerator'] for x in others),
            statistic_reduction_numerator=sum(x['numerator'] for x in records),denominator=r.sc.P**d))


def prove(p,xs,d):
    return assemble(p,prepare(p,xs,d),d)
