"""RFC-0022 §§2.1,2.3,5 quotient product, revealing Draft RFC-0004 A3.

O(NP) byte views/producer for P<=16, plus complete range/hash/MLE consumers.
Every split output byte is consumed; no full norm or private proof admission.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import function_identity as fn

need=r.need
PREFIX=b'stele/research/q26/norm-quotient-product/v1\0'
MASK=(1<<64)-1


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    quotient: int
    divisor: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=norm.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.d;a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<18)*p.identity;external=(p.quotient,p.divisor,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    cert=norm.limbs.derive(norm.column_specs(p.schema)['quotient_product']);k=len(cert['result_caps']);columns=1<<(k-1).bit_length();limit=constants['round_divisor_max'];z=cert['result_max']
    need(columns<=16 and max(cert['carry_caps'])<=382 and 2*max(cert['lhs']+cert['rhs'])<r.sc.P,'FieldBound')
    def child(index,source,caps):return r.Spec(4096*p.identity+index,source,tuple(caps),p.repetitions)
    ranges=dict(quotient=child(1,p.quotient,[32768]*count),offset=child(2,base+1,[limit-1]),low=child(3,base+2,[min(z,MASK)]*count))
    if z>>64:ranges['high']=child(4,base+3,[z>>64]*count)
    caps=list(cert['carry_caps'][1:])+[0]*(16-k)
    for g in range(4):
        family=caps[4*g:4*g+4]
        if any(family):ranges['carry_'+str(g)]=child(5+g,base+4+g,[cap if i<count else 0 for cap in family for i in range(n)])
    widths={name:r.derive(part,d)[3] for name,part in ranges.items()}
    need(widths['low']<=min(columns,8) and ('high' not in widths or columns==16 and widths['high']<=8),'Capacity')
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQ',1,d,p.repetitions,p.identity,*external)+fn.encode(function)
    return dict(ranges=ranges,widths=widths,a=a,n=n,base=base,cert=cert,columns=columns,limit=limit,raw=raw)


def inputs(p,v,qs,b):
    need(type(qs) is list and len(qs)==p.schema.d and all(type(q) is int and 0<=q<=32768 for q in qs) and type(b) is int and 1<=b<=v['limit'],'Input')


def witness(p,qs,b):
    v=derive(p,4);inputs(p,v,qs,b);n=v['n'];padded=qs+[0]*(n-len(qs));carry=[0]*n;values=[];products=[q*b for q in qs]
    for k in range(16):
        carry=[(carry[i]+(q&255)*(b>>(8*k)&255)+((q>>8)*(b>>(8*(k-1))&255) if k else 0))//256 for i,q in enumerate(padded)];values.extend(carry)
    w=dict(quotient=qs.copy(),offset=[b-1],low=[x&MASK for x in products])
    if 'high' in v['ranges']:w['high']=[x>>64 for x in products]
    for g in range(4):
        name='carry_'+str(g)
        if name in v['ranges']:w[name]=values[4*g*n:4*(g+1)*n]
    return w


def divisor_words(v,proof):
    words=proof['offset']['words'];r.vector(words,v['widths']['offset']);value=1+sum(x<<(8*j) for j,x in enumerate(words));need(value<1<<128,'DivisorView')
    return list(value.to_bytes(16,'little'))


def output_words(v,proof):
    result=[]
    for name in ('low','high'):
        if name in v['ranges']:
            words=proof[name]['words'];r.vector(words,v['widths'][name]*v['n']);result.extend(words+[0]*((8-v['widths'][name])*v['n']))
        else:result.extend([0]*(8*v['n']))
    return result


def roots(p,proof):
    v=derive(p,4)
    return [r.source_root(v['ranges']['quotient'],proof['quotient']['words']),r.root(p.divisor,divisor_words(v,proof)),r.root(p.output,output_words(v,proof))]


def expected_roots(p,qs,b,output):
    v=derive(p,4);inputs(p,v,qs,b);need(type(output) is list and len(output)==p.schema.d and all(type(x) is int and 0<=x<1<<128 for x in output),'Output')
    def planes(xs,width):return [x>>(8*k)&255 for k in range(width) for x in xs+[0]*(v['n']-len(xs))]
    return [r.source_root(v['ranges']['quotient'],planes(qs,2)),r.root(p.divisor,list(b.to_bytes(16,'little'))),r.root(p.output,planes(output,16))]


def parts(p,proof,d):
    v=derive(p,d);n,P=v['n'],v['columns'];qs=proof['quotient']['words'];r.vector(qs,2*n);bs=divisor_words(v,proof);carry=[]
    for g in range(4):
        name='carry_'+str(g)
        if name in v['ranges']:
            words=proof[name]['words'];width=v['widths'][name];r.vector(words,4*n*width)
            carry.extend(sum(words[4*n*j+i]<<(8*j) for j in range(width)) for i in range(4*n))
        else:carry.extend([0]*(4*n))
    rows=[qs[:n]*P,qs[n:]*P,[bs[k] for k in range(P) for _ in range(n)],
          [0]*n+[bs[k] for k in range(P-1) for _ in range(n)],[0]*n+carry[:(P-1)*n],output_words(v,proof)[:P*n],carry[:P*n]]
    i=dict(id=16384*p.identity+512,m=v['a']+(P-1).bit_length(),k=0,ids=list(range(v['base']+16,v['base']+23)),
        terms=[(r.sc.scalar(x,d),factors) for x,factors in ((1,[0,2]),(1,[1,3]),(1,[4]),(-1,[5]),(-256,[6]))])
    return i,[[r.sc.scalar(x,d) for x in row] for row in rows]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==len(v['ranges'])+2 and type(states) is list and len(states)==len(v['ranges']) and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,qs,b,d):
    v=derive(p,d);w=witness(p,qs,b);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; split ranges never replace the complete product consumer."""
    v=derive(p,d);proof={name:pairs[name][0] for name in v['ranges']};proof['roots']={name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items() if name!='quotient'}
    t=transcript(v,roots(p,proof)+list(proof['roots'].values()),[pairs[name][1] for name in v['ranges']],d);proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,qs,b,d):
    return assemble(p,prepare(p,qs,b,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);aux=[name for name in v['ranges'] if name!='quotient'];need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(v['ranges'])|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(aux),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,expected[0] if name=='quotient' else proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    need(r.root(p.divisor,divisor_words(v,proof))==expected[1],'Divisor:CommitmentMismatch')
    need(r.root(p.output,output_words(v,proof))==expected[2],'Output:CommitmentMismatch')
    i,tables=parts(p,proof,d);part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==3 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==7 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    t=transcript(v,expected+[proof['roots'][name] for name in aux],[child['state'] for child in children],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('ProductColumns:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in receipt['sc']),denominator=r.sc.P**d))
