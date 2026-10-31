"""RFC-0022 §2.3 left role / revealing Draft RFC-0004 A3.

O(8N) byte views/producer, plus complete range/hash and independent MLE checks.
All factor bytes and high quotient zeros retain their original consumers.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import function_identity as fn

need=r.need
PREFIX=b'stele/research/q26/norm-left/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    product: int
    factor: int
    quotient: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.d;a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<18)*p.identity;external=(p.product,p.factor,p.quotient)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    cert=norm.limbs.derive(norm.column_specs(p.schema)['left']);limit=constants['left_factor_max'];k=len(cert['result_caps'])
    need(k<=8 and max(cert['carry_caps'])<=510 and 2*max(cert['lhs']+cert['rhs'])<r.sc.P,'FieldBound')
    def child(index,source,caps):return r.Spec(4096*p.identity+index,source,tuple(caps),p.repetitions)
    ranges=dict(product=child(1,p.product,[1<<44]*count),quotient=child(2,p.quotient,[32768]*count),offset=child(3,base+1,[limit-1]));caps=list(cert['carry_caps'][1:])+[0]*(8-k)
    for g in range(2):
        family=caps[4*g:4*g+4]
        if any(family):ranges['carry_'+str(g)]=child(4+g,base+2+g,[cap if i<count else 0 for cap in family for i in range(n)])
    widths={name:r.derive(part,d)[3] for name,part in ranges.items()};need(widths['offset']<=2 and all(width<=2 for name,width in widths.items() if name.startswith('carry_')),'Capacity')
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQ',1,d,p.repetitions,p.identity,*external)+fn.encode(function)
    return dict(ranges=ranges,widths=widths,a=a,n=n,base=base,cert=cert,limit=limit,raw=raw)


def inputs(p,v,ts,factor,qs):
    need(type(ts) is list and len(ts)==p.schema.d and all(type(x) is int and 0<=x<=1<<44 for x in ts) and type(qs) is list and len(qs)==p.schema.d and all(type(x) is int and 0<=x<=32768 for x in qs) and type(factor) is int and 1<=factor<=v['limit'],'Input')


def witness(p,ts,factor,qs):
    v=derive(p,4);inputs(p,v,ts,factor,qs);n=v['n'];padded=ts+[0]*(n-len(ts));carry=[0]*n;values=[]
    for k in range(8):
        carry=[(carry[i]+sum((t>>(8*(k-j))&255)*(factor>>(8*j)&255) for j in range(3) if k>=j))//256 for i,t in enumerate(padded)];values.extend(carry)
    w=dict(product=ts.copy(),quotient=qs.copy(),offset=[factor-1])
    for g in range(2):
        name='carry_'+str(g)
        if name in v['ranges']:w[name]=values[4*g*n:4*(g+1)*n]
    return w


def factor_words(v,proof):
    words=proof['offset']['words'];r.vector(words,v['widths']['offset']);value=1+sum(x<<(8*k) for k,x in enumerate(words));need(value<1<<64,'FactorView')
    return list(value.to_bytes(8,'little'))


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(v['ranges']['product'],proof['product']['words']),r.root(p.factor,factor_words(v,proof)),r.source_root(v['ranges']['quotient'],proof['quotient']['words'])]


def expected_roots(p,ts,factor,qs):
    v=derive(p,4);inputs(p,v,ts,factor,qs)
    def planes(xs,width):return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(v['n']-len(xs))]
    return [r.source_root(v['ranges']['product'],planes(ts,8)),r.root(p.factor,list(factor.to_bytes(8,'little'))),r.source_root(v['ranges']['quotient'],planes(qs,2))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];ts=proof['product']['words'];qs=proof['quotient']['words'];r.vector(ts,8*n);r.vector(qs,2*n);fs=factor_words(v,proof);carry=[]
    for g in range(2):
        name='carry_'+str(g)
        if name in v['ranges']:
            words=proof[name]['words'];width=v['widths'][name];r.vector(words,4*n*width);carry.extend(sum(words[4*n*j+i]<<(8*j) for j in range(width)) for i in range(4*n))
        else:carry.extend([0]*(4*n))
    # RFC-0022 §2.3: all eight result columns remain, including q's high zeros.
    rows=[]
    for j in range(3):rows.extend(([0]*(j*n)+ts[:(8-j)*n],[fs[j]]*(8*n)))
    rows.extend(([0]*n+carry[:7*n],qs+[0]*(6*n),carry))
    i=dict(id=16384*p.identity+512,m=v['a']+3,k=0,ids=list(range(v['base']+16,v['base']+25)),terms=[(r.sc.scalar(x,d),factors) for x,factors in ((1,[0,1]),(1,[2,3]),(1,[4,5]),(1,[6]),(-1,[7]),(-256,[8]))])
    return i,[[r.sc.scalar(x,d) for x in row] for row in rows]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==len(v['ranges'])+1 and type(states) is list and len(states)==len(v['ranges']) and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,ts,factor,qs,d):
    v=derive(p,d);w=witness(p,ts,factor,qs);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; bounded supplied q still requires faithful multiplication."""
    v=derive(p,d);proof={name:pairs[name][0] for name in v['ranges']};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items() if name not in ('product','quotient')}
    t=transcript(v,roots(p,proof)+list(proof['roots'].values()),[pairs[name][1] for name in v['ranges']],d);proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,ts,factor,qs,d):
    return assemble(p,prepare(p,ts,factor,qs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);aux=[name for name in v['ranges'] if name not in ('product','quotient')];need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(v['ranges'])|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(aux),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        target=expected[0] if name=='product' else expected[2] if name=='quotient' else proof['roots'][name]
        try:children.append(r.verify(child,target,proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    need(r.root(p.factor,factor_words(v,proof))==expected[1],'Factor:CommitmentMismatch');i,tables=parts(p,proof,d);part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==3 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==9 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    t=transcript(v,expected+[proof['roots'][name] for name in aux],[child['state'] for child in children],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('LeftColumns:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in receipt['sc']),denominator=r.sc.P**d))
