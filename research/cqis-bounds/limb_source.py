"""Q26/Q31 limb input consumers: Draft RFC-0004 A3, revealing A3/range research."""
from dataclasses import dataclass
import struct
import limbs
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/limb-source/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: limbs.Spec
    identity: int
    source: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<54 and type(p.source) is int and 2<=p.source<1<<64,'Spec')
    need(type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=limbs.derive(p.schema); s=p.schema; a=(s.count-1).bit_length(); n=1<<a; rows=2*n
    size=max(1,(max(s.left_max,s.right_max).bit_length()+7)//8); b=(size-1).bit_length(); width=1<<b
    planes=width*(2 if s.radix_bits==4 else 1); cells=rows*planes
    need(rows<=4096 and (s.radix_bits==8 or cells<=4096),'Capacity')
    base=(1<<63)+256*p.identity; need(not base<=p.source<base+256,'Spec')
    caps=(s.left_max,)*s.count+(0,)*(n-s.count)+(s.right_max,)*s.count+(0,)*(n-s.count)
    whole=r.Spec(4*p.identity+1,base,caps,p.repetitions)
    nibbles=r.Spec(4*p.identity+2,p.source,(15,)*cells,p.repetitions) if s.radix_bits==4 else None
    r.derive(whole,d)
    if nibbles is not None: r.derive(nibbles,d)
    raw=PREFIX+struct.pack('<BBBBQQI',1,d,p.repetitions,s.radix_bits,p.identity,p.source,s.count)
    raw+=s.left_max.to_bytes(20,'little')+s.right_max.to_bytes(20,'little')
    return dict(a=a,b=b,n=n,width=width,rows=rows,planes=planes,cells=cells,base=base,
                whole=whole,nibbles=nibbles,raw=raw,cert=cert)


def source(p,left,right):
    """Exact layout of existing operand digit tuples; this does not enforce their range."""
    v=derive(p,4); result=[]
    for key,rows in (('left',left),('right',right)):
        size=len(v['cert'][key+'_caps'])
        need(type(rows) is tuple and len(rows)==p.schema.count and
             all(type(row) is tuple and len(row)==size for row in rows),'SourceShape')
    for j in range(v['planes']):
        for key,rows in (('left',left),('right',right)):
            size=len(v['cert'][key+'_caps'])
            result.extend(row[j] if j<size else 0 for row in rows)
            result.extend([0]*(v['n']-p.schema.count))
    r.vector(result,v['cells'])
    return result


def source_root(p,digits):
    r.vector(digits,derive(p,4)['cells'])
    return r.root(p.source,digits)


def packing(p,digits,words,d):
    v=derive(p,d); rows=v['rows']; r.vector(digits,v['cells']); r.vector(words,rows*v['width'])
    if p.schema.radix_bits==8:
        ids=[p.source,v['base']]; terms=[(1,[0]),(-1,[1])]; tables=[digits,words]
    else:
        low=[x for j in range(v['width']) for x in digits[(2*j)*rows:(2*j+1)*rows]]
        high=[x for j in range(v['width']) for x in digits[(2*j+1)*rows:(2*j+2)*rows]]
        ids=[v['base']+8,v['base']+9,v['base']]; terms=[(1,[0]),(16,[1]),(-1,[2])]; tables=[low,high,words]
    return dict(id=16*p.identity+12,m=v['a']+v['b']+1,k=0,ids=ids,
                terms=[(r.sc.scalar(c,d),factors) for c,factors in terms]),[[r.sc.scalar(x,d) for x in xs] for xs in tables]


def transcript(p,expected,word_root,d,states):
    v=derive(p,d)
    need(type(states) is list and len(states)==(2 if v['nibbles'] is not None else 1) and
         all(type(x) is bytes and len(x)==32 for x in [expected,word_root,*states]),'State')
    return r.scalar.Transcript(v['raw']+expected+word_root+b''.join(states),d)


def assemble(p,digits,word_pair,nibble_pair,d):
    """Compose arithmetic proofs; each nested proof and all packing claims still require verification."""
    v=derive(p,d); word,word_state=word_pair
    need(type(word) is dict and type(word.get('words')) is list,'ProofShape')
    need((nibble_pair is not None)==(v['nibbles'] is not None),'ProofShape')
    word_root=r.source_root(v['whole'],word['words']); expected=source_root(p,digits)
    states=([nibble_pair[1]] if nibble_pair is not None else [])+[word_state]
    t=transcript(p,expected,word_root,d,states); i,tables=packing(p,digits,word['words'],d)
    proof=dict(digits=list(digits),word_root=word_root,word=word,
               nibbles=nibble_pair[0] if nibble_pair is not None else None,packing=r.zero_prove(t,i,tables))
    return proof,t.state


def prove(p,digits,d):
    v=derive(p,d); r.vector(digits,v['cells'])
    need(all(x<1<<p.schema.radix_bits for x in digits),'Range')
    values=[sum(digits[j*v['rows']+i]<<(p.schema.radix_bits*j) for j in range(v['planes'])) for i in range(v['rows'])]
    nibble_pair=r.prove(v['nibbles'],digits,d) if v['nibbles'] is not None else None
    return assemble(p,digits,r.prove(v['whole'],values,d),nibble_pair,d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is bytes and len(expected)==32,'Root')
    need(type(proof) is dict and set(proof)=={'digits','word_root','word','nibbles','packing'},'ProofShape')
    need(type(proof['word_root']) is bytes and len(proof['word_root'])==32,'Root')
    need(type(proof['word']) is dict and (type(proof['nibbles']) is dict if v['nibbles'] is not None else proof['nibbles'] is None),'ProofShape')
    digits=proof['digits']; r.vector(digits,v['cells'])
    need(source_root(p,digits)==expected,'CommitmentMismatch')
    children=[]; nibble=None
    if v['nibbles'] is not None:
        try: nibble=r.verify(v['nibbles'],expected,proof['nibbles'],d)
        except ValueError as error: raise ValueError('Nibbles:'+str(error)) from None
        children.append(nibble)
    try: word=r.verify(v['whole'],proof['word_root'],proof['word'],d)
    except ValueError as error: raise ValueError('WholeWord:'+str(error)) from None
    children.append(word)
    i,tables=packing(p,digits,proof['word']['words'],d); part=proof['packing']
    need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip']
         and type(part['rounds']) is list and len(part['rounds'])==i['m'] and
         all(type(row) is list and len(row)==2 for row in part['rounds']) and
         type(part['final']) is list and len(part['final'])==len(i['ids']) and
         all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
    t=transcript(p,expected,proof['word_root'],d,[child['state'] for child in children])
    try: receipt,_=r.zc.verify(t,i,part,tables)
    except ValueError as error: raise ValueError('LimbPacking:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,word=word,nibbles=nibble,packing=receipt,draws=dict(t.draws),
                account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],
                    lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),
                    range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in receipt['sc']),
                    denominator=r.sc.P**d))
