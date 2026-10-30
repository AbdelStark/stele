"""Q26/Q31 actual reciprocal membership: RFC-0021 §2.3 / Draft RFC-0004 A3.

Complete49152-tuple lookup and fraction trees; no formula-only acceptance.
"""
from dataclasses import dataclass
from functools import lru_cache
import struct
import norm_bounds as norm
import wide_range as r
import function_identity as fn

need=r.need
TABLE=fn.table.Descriptor('rsqrt_q',1,b'')
PREFIX=b'stele/research/q26/norm-rsqrt/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    mantissa: int
    output: int
    repetitions: int


def metadata(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<50 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+4096*p.identity;ids=(p.mantissa,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+4096 for x in ids) and len(set(ids))==2,'Spec')
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed));rep=fn.Representation(function,3,b'')
    need(fn.dependencies(rep)==(TABLE,),'Table:Dependency')
    raw=PREFIX+struct.pack('<BBBQQQ',1,d,p.repetitions,p.identity,*ids)+fn.encode(function)+fn.encode_representation(rep)+fn.table.table_id(TABLE)
    return dict(base=base,raw=raw)


@lru_cache(maxsize=1)
def table():
    """Immutable complete definition; only valid tuples enter membership."""
    need(fn.table.shape(TABLE)==(49152,65536,2),'Table:Shape');rows=fn.table.canonical_rows(TABLE)
    need(len(rows)==65536 and rows[49152:]==((0,0),)*16384,'Table:Padding')
    return rows,rows[:49152]


def derive(p,d):
    v=metadata(p,d);full,valid=table()
    plan=dict(id=64*p.identity+1,m=0,b=0,r=p.repetitions,sources=(p.mantissa,p.output),
              mus=tuple(v['base']+1+j for j in range(p.repetitions)),table=valid,sigma=(1,))
    return dict(**v,rows=full,lookup=plan)


def witness(p,mantissa):
    metadata(p,4);need(type(mantissa) is int and 16384<=mantissa<=65535,'Mantissa')
    return table()[1][mantissa-16384][1]


def expected_roots(p,mantissa,output):
    metadata(p,4);r.vector([mantissa,output],2)
    return [r.root(p.mantissa,[mantissa]),r.root(p.output,[output])]


def transcript(v,roots,state,d):
    need(type(roots) is list and len(roots)==2 and all(type(x) is bytes and len(x)==32 for x in roots+[state]),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots)+state,d)


def assemble(p,pair,d):
    """Producer only; the actual full lookup remains mandatory in verify."""
    v=derive(p,d);roots=r.lu.source_roots(v['lookup'],pair[0]['sources'])
    return dict(lookup=pair[0]),transcript(v,roots,pair[1],d).state


def prove(p,mantissa,d):
    v=derive(p,d);proof,out=r.lu.prove(v['lookup'],[[mantissa],[witness(p,mantissa)]],d)
    return assemble(p,(proof,out['state']),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'lookup'},'ProofShape')
    try:
        part=proof['lookup'];need(type(part) is dict and 'sources' in part,'ProofShape')
        need(r.lu.source_roots(v['lookup'],part['sources'])==expected,'CommitmentMismatch')
        out=r.lu.verify(v['lookup'],expected,part,d)
    except ValueError as error:raise ValueError('Lookup:'+str(error)) from None
    t=transcript(v,expected,out['state'],d)
    return dict(state=t.state,lookup=out,draws=dict(t.draws),account=out['account'])
