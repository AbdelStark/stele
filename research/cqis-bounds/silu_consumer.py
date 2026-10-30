"""Q26/Q31 SiLU: RFC-0021 §§2.2–4 / RFC-0008 A4, revealing research.

Draft A2 full-table lookup consumes actual signed-byte sources; no private PCS.
Field views cost O(N), plus complete table generation and inherited consumers.
"""
from dataclasses import dataclass
from functools import lru_cache
import struct
import signed_source as ss
import function_identity as fn

r=ss.r
need=r.need
NAMES=('input','output')
AUX=('input_magnitude','output_magnitude')
PREFIX=b'stele/research/q26/silu-consumer/v1\0'


@dataclass(frozen=True)
class Spec:
    representation: fn.Representation
    count: int
    identity: int
    source: int
    output: int
    repetitions: int


def metadata(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.count) is int and p.count>=1,'Spec'); need(p.count<=2048,'Capacity')
    base=(1<<63)+(1<<18)*p.identity; external=(p.source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and p.source!=p.output,'Spec')
    rep=p.representation
    need(type(rep) is fn.Representation and type(rep.function) is fn.Function and rep.function.name=='silu_q'
         and type(rep.mode) is int and rep.mode==0 and type(rep.params) is bytes and not rep.params,'Spec')
    f=rep.function; need(type(f.version) is int and f.version==1 and type(f.params) is bytes and len(f.params)==2,'Spec')
    fraction,output=f.params; need(fraction<=30 and output<=14,'Spec')
    # RFC-0021 §3 totality: E>F overflows at t=32767. This is rejection only;
    # E<=F still requires every canonical row and its full precision schedule.
    need(output<=fraction,'Table:Overflow')
    signed={name:ss.Spec(512*p.identity+j+1,source,base+j+1,16,p.count,p.repetitions) for j,(name,source) in enumerate(zip(NAMES,external))}
    for child in signed.values(): ss.derive(child,d)
    a=(p.count-1).bit_length()
    raw=PREFIX+struct.pack('<BBBQQQI',1,d,p.repetitions,p.identity,p.source,p.output,p.count)+fn.encode(f)+fn.encode_representation(rep)
    return dict(**signed,a=a,n=1<<a,base=base,raw=raw)


@lru_cache(maxsize=4,typed=True)
def table(rep):
    """Only expected definitions enter this immutable complete-table cache."""
    try: rows=fn.table.canonical_rows(fn.dependencies(rep)[0])
    except ValueError as error: raise ValueError('Table:'+str(error)) from None
    return rows,tuple(tuple(x%r.sc.P for x in row) for row in rows)


def derive(p,d):
    v=metadata(p,d); rows,lifted=table(p.representation); base=v['base']
    plan=dict(id=4096*p.identity+65,m=v['a'],b=v['a'],r=p.repetitions,sources=(base+3,base+4),
              mus=tuple(base+5+j for j in range(p.repetitions)),table=lifted,sigma=(1,)*p.count+(0,)*(v['n']-p.count))
    return dict(**v,rows=rows,lookup=plan)


def lift(raw,sign,n):
    r.vector(raw,2*n); r.vector(sign,2*n)
    return [(raw[i]+256*raw[n+i]-65536*sign[i])%r.sc.P for i in range(n)]


def columns(v,proof):
    return [lift(proof[name]['ranges'][0]['words'],proof[name]['ranges'][2]['words'],v['n']) for name in NAMES]


def witness(p,xs):
    v=derive(p,4); ss.witness(v['input'],xs)
    return [v['rows'][x+32768][1] for x in xs]


def expected_roots(p,xs,ys):
    v=metadata(p,4); result=[]
    for name,values in zip(NAMES,(xs,ys)):
        raw=ss.witness(v[name],values)[0]; child=ss.derive(v[name],4)['ranges'][0]
        result.append(r.source_root(child,r.witness(child,raw)[0]))
    return result


def transcript(v,roots,states,d):
    need(type(roots) is list and len(roots)==6 and type(states) is list and len(states)==3 and
         all(type(x) is bytes and len(x)==32 for x in roots+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots+states),d)


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; only verify authorizes acceptance."""
    v=derive(p,d); proof={name:pairs[name][0] for name in (*NAMES,'lookup')}
    proof['roots']={aux:r.root(v['base']+j+1,proof[name]['ranges'][1]['words']) for j,(name,aux) in enumerate(zip(NAMES,AUX))}
    raw=[r.source_root(ss.derive(v[name],d)['ranges'][0],proof[name]['ranges'][0]['words']) for name in NAMES]
    roots=raw+[proof['roots'][aux] for aux in AUX]+r.lu.source_roots(v['lookup'],columns(v,proof))
    return proof,transcript(v,roots,[pairs[name][1] for name in (*NAMES,'lookup')],d).state


def prove(p,xs,d):
    v=derive(p,d); ys=witness(p,xs); pairs={name:ss.prove(v[name],values,d) for name,values in zip(NAMES,(xs,ys))}
    part,receipt=r.lu.prove(v['lookup'],columns(v,{name:pairs[name][0] for name in NAMES}),d)
    pairs['lookup']=(part,receipt['state'])
    return assemble(p,pairs,d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'input','output','lookup','roots'} and type(proof['roots']) is dict and set(proof['roots'])==set(AUX),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root'); children=[]
    for name,aux,root in zip(NAMES,AUX,expected):
        try: children.append(ss.verify(v[name],[root,proof['roots'][aux]],proof[name],d))
        except ValueError as error: raise ValueError(name.title()+':'+str(error)) from None
    actual=columns(v,proof)
    try:
        part=proof['lookup']; need(type(part) is dict and 'sources' in part,'ProofShape')
        r.lu.source_roots(v['lookup'],part['sources'])
        need(part['sources']==actual,'SourceJoin')
        lookup_roots=r.lu.source_roots(v['lookup'],actual); lookup=r.lu.verify(v['lookup'],lookup_roots,part,d)
    except ValueError as error: raise ValueError('Lookup:'+str(error)) from None
    roots=expected+[proof['roots'][aux] for aux in AUX]+lookup_roots
    t=transcript(v,roots,[child['state'] for child in children]+[lookup['state']],d)
    accounts=[child['account'] for child in children]; la=lookup['account']
    return dict(state=t.state,children=children,lookup=lookup,draws=dict(t.draws),
        account=dict(identities=sum((x['identities'] for x in accounts),[])+[(la['identity_numerator'],la['identity_power'])],
            lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts)+la['reduction_numerator'],
            range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),denominator=r.sc.P**d))
