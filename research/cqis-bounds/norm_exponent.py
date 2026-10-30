"""Q26/Q31 RMSNorm factors: RFC-0021 §2.3 / RFC-0022 §2.3, Draft A3.

One bounded selection, two complete A3s and one A1; full-reveal research only.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import function_identity as fn

need=r.need
PREFIX=b'stele/research/q26/norm-exponent/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<50 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    norm.constants(p.schema); base=(1<<63)+4096*p.identity
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+4096 for x in (p.source,p.output)) and p.source!=p.output,'Spec')
    indicator=r.Spec(64*p.identity+1,base+1,(1,)*33+(0,)*31,p.repetitions); r.derive(indicator,d)
    need(64<r.sc.P,'FieldBound')  # RFC-0022 §2.3: a bit sum of1 has one integer selection.
    s=p.schema; function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQ',1,d,p.repetitions,p.identity,p.source,p.output)+fn.encode(function)
    return dict(base=base,indicator=indicator,raw=raw)


def public_tables():
    """RFC-0022 §2.3: fixed index/factor-byte MLE tables, never witness powers."""
    rows=[]
    for i in range(33):
        a=i-23; rows.append(list((1<<(2*max(-a,0))).to_bytes(8,'little')+(1<<(2*max(a,0))).to_bytes(8,'little')))
    return list(range(33))+[0]*31,[rows[i][j] if i<33 else 0 for j in range(16) for i in range(64)]


def witness(p,a):
    derive(p,4); need(type(a) is int and -23<=a<=9,'Exponent')
    return [a+23],list((4**max(-a,0)).to_bytes(8,'little')+(4**max(a,0)).to_bytes(8,'little')),[int(i==a+23) for i in range(64)]


def roots(p,offset,factors):
    derive(p,4); r.vector(offset,1); r.vector(factors,16)
    return [r.root(p.source,offset),r.root(p.output,factors)]


def expected_roots(p,a):
    offset,factors,_=witness(p,a)
    return roots(p,offset,factors)


def parts(p,proof,d):
    v=derive(p,d); base=v['base']; offset,factors,indicator=proof['offset'],proof['factors'],proof['indicator']['words']
    for xs,size in ((offset,1),(factors,16),(indicator,64)): r.vector(xs,size)
    indices,grid=public_tables()
    def item(name,index,m,ids,rows):
        return name,dict(id=256*p.identity+128+index,m=m,k=0,ids=ids,
            terms=[(r.sc.scalar(1,d),[0,1]),(r.sc.scalar(-1,d),[0,2])]),[[r.sc.scalar(x,d) for x in xs] for xs in rows]
    return [item('Exponent',0,6,[base+1,base+8,base+9],[indicator,offset*64,indices]),
            item('Factors',1,10,[base+10,base+11,base+12],[indicator*16,[x for x in factors for _ in range(64)],grid])]


def one_descriptor(p,v,d):
    return dict(id=256*p.identity+130,m=6,ids=[v['base']+1],terms=[(r.sc.scalar(1,d),[0])],sum=r.sc.scalar(1,d))


def transcript(v,bound,state,d):
    need(type(bound) is list and len(bound)==3 and all(type(x) is bytes and len(x)==32 for x in bound+[state]),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound)+state,d)


def prepare(p,a,d):
    v=derive(p,d); offset,factors,indicator=witness(p,a)
    return r.prove(v['indicator'],indicator,d),offset,factors


def assemble(p,pair,offset,factors,d):
    """Arithmetic producer for supplied sources; verify alone confers acceptance."""
    v=derive(p,d); expected=roots(p,offset,factors); proof=dict(offset=list(offset),factors=list(factors),indicator=pair[0])
    proof['indicator_root']=r.source_root(v['indicator'],proof['indicator']['words'])
    t=transcript(v,expected+[proof['indicator_root']],pair[1],d)
    proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    proof['one'],_=r.sc.prove(t,one_descriptor(p,v,d),[[r.sc.scalar(x,d) for x in proof['indicator']['words']]])
    return proof,t.state


def prove(p,a,d):
    return assemble(p,*prepare(p,a,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==2 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'offset','factors','indicator','indicator_root','zero','one'},'ProofShape')
    need(type(proof['indicator_root']) is bytes and len(proof['indicator_root'])==32,'Root')
    actual=roots(p,proof['offset'],proof['factors'])
    for name,got,want in zip(('Offset','Factors'),actual,expected): need(got==want,name+':CommitmentMismatch')
    try: child=r.verify(v['indicator'],proof['indicator_root'],proof['indicator'],d)
    except ValueError as error: raise ValueError('Indicator:'+str(error)) from None
    need(type(proof['zero']) is list and len(proof['zero'])==2,'ProofShape')
    t=transcript(v,expected+[proof['indicator_root']],child['state'],d); records=[]; claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
             and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(xs) is list and len(xs)==3 for xs in part['rounds'])
             and type(part['final']) is list and len(part['final'])==3 and all(type(xs) is list and len(xs)==1 for xs in part['final']),'ProofShape')
        try: receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error: raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']); claims.extend(receipt['claims'])
    part=proof['one']
    need(type(part) is dict and set(part)=={'rounds','final'} and type(part['rounds']) is list and len(part['rounds'])==6
         and all(type(xs) is list and len(xs)==2 for xs in part['rounds']) and type(part['final']) is list and len(part['final'])==1,'ProofShape')
    try:
        r.lu.ft.fields(sum(part['rounds'],[])+part['final'],d); one=r.sc.verify_reduction(t,one_descriptor(p,v,d),part)
        need(r.zc.folded([r.sc.scalar(x,d) for x in proof['indicator']['words']],one['point'])==one['claims'][0][1],'ClaimMismatch')
    except ValueError as error: raise ValueError('OneHot:'+str(error)) from None
    a=child['account']
    return dict(state=t.state,indicator=child,sc=records,claims=claims,one=one,draws=dict(t.draws),
        account=dict(identities=[(a['identity_numerator'],a['identity_power'])],lookup_reduction_numerator=a['lookup_reduction_numerator'],
            range_reduction_numerator=a['range_reduction_numerator']+sum(x['numerator'] for x in records),
            selection_reduction_numerator=one['sc']['numerator'],denominator=r.sc.P**d))
