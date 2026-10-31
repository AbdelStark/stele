"""Draft RFC-0004 A3/A8: exact residual alignment from actual signed sources.

O(N) byte views and one batched A3, plus complete signed/range/hash consumers.
This proves only the aligned offset; residual sign and rounding remain separate.
"""
from dataclasses import dataclass
import struct
import residual_bounds as residual
import signed_source as ss

r=ss.r
need=r.need
PREFIX=b'stele/research/q26/residual-aligned/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: residual.Spec
    identity: int
    left: int
    right: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=residual.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    count=p.schema.dimension;need(count<=16384,'Capacity');a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<18)*p.identity;external=(p.left,p.right,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    signed={name:ss.Spec(512*p.identity+index,source,base+index,16,count,p.repetitions) for index,(name,source) in enumerate((('left',p.left),('right',p.right)),1)}
    for child in signed.values():ss.derive(child,d)
    s=p.schema;f=max(s.left_fraction,s.right_fraction,s.output_fraction);shifts=(f-s.left_fraction,f-s.right_fraction);caps=[];incoming=0
    for k in range(8):
        raw=sum(255*(1<<(shift%8)) for shift in shifts if shift//8<=k<shift//8+2);outgoing=(raw+incoming)//256
        need(outgoing<=255 and 2*max(raw+incoming,255+256*outgoing)<r.sc.P,'FieldBound');caps.append(outgoing);incoming=outgoing
    need(caps[-1]==0,'FieldBound')
    ranges=dict(output=r.Spec(4096*p.identity+65,base+3,(constants['offset_max'],)*count,p.repetitions))
    for g in range(2):
        family=caps[4*g:4*g+4]
        if any(family):ranges['carry_'+str(g)]=r.Spec(4096*p.identity+66+g,base+4+g,tuple(cap if i<count else 0 for cap in family for i in range(n)),p.repetitions)
    for child in ranges.values():r.derive(child,d)
    width=r.derive(ranges['output'],d)[3];need(width<=8,'Capacity')
    raw=PREFIX+struct.pack('<BBBQQQQIBBB',1,d,p.repetitions,p.identity,*external,count,s.left_fraction,s.right_fraction,s.output_fraction)
    return dict(**signed,ranges=ranges,constants=constants,shifts=shifts,carry_caps=tuple(caps),a=a,n=n,base=base,width=width,raw=raw)


def witness(p,xs,ys):
    v=derive(p,4);need(type(xs) is list and type(ys) is list,'Input');residual.inputs(p.schema,tuple(xs),tuple(ys));n=v['n'];rows=[z+[0]*(n-len(z)) for z in (xs,ys)];carry=[0]*n;cs=[]
    for k in range(8):
        carry=[(carry[i]+sum((((row[i]+32768)>>(8*(k-shift//8)))&255)*(1<<(shift%8)) for row,shift in zip(rows,v['shifts']) if i<p.schema.dimension and shift//8<=k<shift//8+2))//256 for i in range(n)];cs.extend(carry)
    c=v['constants'];w=dict(output=[(x+32768)*c['left_factor']+(y+32768)*c['right_factor'] for x,y in zip(xs,ys)])
    for g in range(2):
        name='carry_'+str(g)
        if name in v['ranges']:w[name]=cs[4*g*n:4*(g+1)*n]
    return w


def output_words(v,proof):
    words=proof['output']['words'];r.vector(words,v['width']*v['n']);return words+[0]*((8-v['width'])*v['n'])


def roots(p,proof):
    v=derive(p,4)
    return [r.root(source,proof[name]['ranges'][0]['words']) for name,source in (('left',p.left),('right',p.right))]+[r.root(p.output,output_words(v,proof))]


def expected_roots(p,xs,ys,output):
    v=derive(p,4);need(type(xs) is list and type(ys) is list,'Input');residual.inputs(p.schema,tuple(xs),tuple(ys))
    need(type(output) is list and len(output)==p.schema.dimension and all(type(x) is int and 0<=x<1<<64 for x in output),'Output')
    def planes(values,width):return [x>>(8*k)&255 for k in range(width) for x in values+[0]*(v['n']-len(values))]
    return [r.root(source,planes([x%65536 for x in values],2)) for source,values in ((p.left,xs),(p.right,ys))]+[r.root(p.output,planes(output,8))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];rows=[];carry=[]
    for name,shift in zip(('left','right'),v['shifts']):
        words=proof[name]['ranges'][0]['words'];r.vector(words,2*n)
        # Verified two's-complement bytes map to x+32768 by flipping the top
        # bit. The offset belongs only to real rows, never to zero padding.
        offset=words[:n]+[(words[n+i]^128) if i<p.schema.dimension else 0 for i in range(n)]
        rows.append([offset[(k-shift//8)*n+i]*(1<<(shift%8)) if shift//8<=k<shift//8+2 else 0 for k in range(8) for i in range(n)])
    for g in range(2):
        name='carry_'+str(g)
        if name in v['ranges']:r.vector(proof[name]['words'],4*n);carry.extend(proof[name]['words'])
        else:carry.extend([0]*(4*n))
    rows.extend(([0]*n+carry[:-n],output_words(v,proof),carry))
    instance=dict(id=16384*p.identity+512,m=v['a']+3,k=0,ids=list(range(v['base']+16,v['base']+21)),terms=[(r.sc.scalar(value,d),[index]) for index,value in enumerate((1,1,1,-1,-256))])
    return instance,[[r.sc.scalar(x,d) for x in row] for row in rows]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==5+len(v['ranges']) and type(states) is list and len(states)==2+len(v['ranges']) and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,ys,d):
    v=derive(p,d);w=witness(p,xs,ys)
    return dict(left=ss.prove(v['left'],xs,d),right=ss.prove(v['right'],ys,d),**{name:r.prove(child,w[name],d) for name,child in v['ranges'].items()})


def assemble(p,pairs,d):
    """Producer only; all original child consumers remain mandatory."""
    v=derive(p,d);names=['left','right']+list(v['ranges']);proof={name:pairs[name][0] for name in names}
    proof['roots']={name:r.root(v['base']+index,proof[name]['ranges'][1]['words']) for index,name in enumerate(('left','right'),1)}
    proof['roots'].update({name:r.source_root(child,proof[name]['words']) for name,child in v['ranges'].items()})
    t=transcript(v,roots(p,proof)+list(proof['roots'].values()),[pairs[name][1] for name in names],d);proof['zero']=r.zero_prove(t,*parts(p,proof,d))
    return proof,t.state


def prove(p,xs,ys,d):
    return assemble(p,prepare(p,xs,ys,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);names=['left','right']+list(v['ranges']);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(names)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(names),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for index,name in enumerate(('left','right')):
        try:children.append(ss.verify(v[name],[expected[index],proof['roots'][name]],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for name,child in v['ranges'].items():
        try:children.append(r.verify(child,proof['roots'][name],proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    need(r.root(p.output,output_words(v,proof))==expected[2],'Output:CommitmentMismatch');i,tables=parts(p,proof,d);part=proof['zero']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==2 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==5 and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
    t=transcript(v,expected+[proof['roots'][name] for name in names],[child['state'] for child in children],d)
    try:receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error:raise ValueError('AlignedColumns:'+str(error)) from None
    signed=[child['account'] for child in children[:2]];ranges=[child['account'] for child in children[2:]]
    account=dict(identities=sum((item['identities'] for item in signed),[])+[(item['identity_numerator'],item['identity_power']) for item in ranges],lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in signed+ranges),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in signed+ranges)+sum(row['numerator'] for row in receipt['sc']),denominator=r.sc.P**d)
    return dict(state=t.state,children=children,sc=receipt['sc'],claims=receipt['claims'],draws=dict(t.draws),account=account)
