"""RFC-0004 A3/A6 / RFC-0009 A2: consumed restored attention value sources.

O(N+R) views and A3 producers, plus complete revealing range/source consumers.
Prepared projection-row ownership and weighted-sum composition remain separate.
"""
from dataclasses import dataclass
import struct
import attention_sum_bounds as bounds
import signed_source as ss

r=ss.r
need=r.need
PREFIX=b'stele/research/q26/attention-values/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    positions: tuple
    identity: int
    source: int
    scale_source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');cert=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.positions) is tuple and 1<=len(p.positions)<=16384,'Spec');rows=len(p.positions);count=rows*p.schema.width;need(count<=16384,'Capacity')
    need(all(type(x) is int and 0<=x<p.schema.length for x in p.positions) and all(x<y for x,y in zip(p.positions,p.positions[1:])),'Spec')
    a=(count-1).bit_length();ar=(rows-1).bit_length();n=1<<a;nr=1<<ar;base=(1<<63)+(1<<18)*p.identity;external=(p.source,p.scale_source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    dynamic=p.schema.value_mode=='dynamic';cap=cert['code_max'];S=cert['restored_max'];bound=max(2*S+256*cert['scale_max'],S+255*cert['scale_max']);need(2*bound<r.sc.P,'FieldBound')
    signed=ss.Spec(512*p.identity+1,p.source,base+1,8,count,p.repetitions);ss.derive(signed,d)
    ranges=dict(magnitude=r.Spec(4096*p.identity+65,base+1,(cap,)*count,p.repetitions),output=r.Spec(4096*p.identity+66,base+2,(2*S,)*count,p.repetitions))
    if dynamic:ranges.update(scale=r.Spec(4096*p.identity+67,p.scale_source,(259,)*rows,p.repetitions),nonzero=r.Spec(4096*p.identity+68,base+3,(1,)*rows,p.repetitions),predecessor=r.Spec(4096*p.identity+69,base+4,(258,)*rows,p.repetitions))
    for child in ranges.values():r.derive(child,d)
    bo=r.derive(ranges['output'],d)[1];need(bo<=2,'Capacity');aux=('magnitude','output')+(('nonzero','predecessor') if dynamic else ())
    s=p.schema;raw=PREFIX+struct.pack('<BBBQQQQI',1,d,p.repetitions,p.identity,*external,rows)+struct.pack('<IHBBBBH',s.length,s.width,s.fraction,s.exponent,int(dynamic),int(s.accumulation=='block1024'),s.scale)
    raw+=b''.join(struct.pack('<I',x) for x in p.positions)
    return dict(signed=signed,ranges=ranges,names=('source',)+tuple(ranges),aux=aux,a=a,ar=ar,n=n,nr=nr,count=count,rows=rows,base=base,cap=cap,S=S,bound=bound,bo=bo,dynamic=dynamic,raw=raw)


def witness(p,codes,scales):
    v=derive(p,4);need(type(codes) is list and len(codes)==v['count'] and all(type(x) is int and abs(x)<=v['cap'] for x in codes),'Input')
    need(type(scales) is list and len(scales)==v['rows'] and all(type(s) is int and (0<=s<=259 if v['dynamic'] else s==p.schema.scale) for s in scales),'Input')
    need(all(scales[j//p.schema.width]!=0 or code==0 for j,code in enumerate(codes)),'Input')
    return dict(magnitude=list(map(abs,codes)),output=[v['S']+code*scales[j//p.schema.width] for j,code in enumerate(codes)],scale=scales.copy(),nonzero=[int(s!=0) for s in scales],predecessor=[max(s-1,0) for s in scales])


def full_output(v,words):
    r.vector(words,v['n']*(1<<v['bo']));return words+[0]*(v['n']*(4-(1<<v['bo'])))


def scale_words(p,v,proof):
    if v['dynamic']:words=proof['scale']['words'];r.vector(words,2*v['nr']);return words
    return [p.schema.scale>>(8*j)&255 if i<v['rows'] else 0 for j in range(2) for i in range(v['nr'])]


def roots(p,proof):
    v=derive(p,4);source=r.source_root(ss.derive(v['signed'],4)['ranges'][0],proof['source']['ranges'][0]['words'])
    return [source,r.root(p.scale_source,scale_words(p,v,proof)),r.root(p.output,full_output(v,proof['output']['words']))]


def expected_roots(p,codes,scales):
    v=derive(p,4);w=witness(p,codes,scales);nr,n=v['nr'],v['n'];values=w['output']+[0]*(n-v['count'])
    return [r.root(p.source,[x%256 for x in codes]+[0]*(n-v['count'])),r.root(p.scale_source,[s>>(8*j)&255 for j in range(2) for s in scales+[0]*(nr-v['rows'])]),r.root(p.output,[x>>(8*j)&255 for j in range(4) for x in values])]


def unpack(child,words,d):
    _,_,n,width,_,_=r.derive(child,d);r.vector(words,n*width);return [sum(words[j*n+i]<<(8*j) for j in range(width)) for i in range(n)]


def parts(p,proof,d):
    v=derive(p,d);n,nr,base=v['n'],v['nr'],v['base'];raw=proof['source']['ranges'][0]['words'];sign=proof['source']['ranges'][2]['words'];r.vector(raw,n);r.vector(sign,2*n)
    sw=scale_words(p,v,proof);scales=[sw[i]+256*sw[nr+i] for i in range(nr)];broadcast=[scales[i//p.schema.width] if i<v['count'] else 0 for i in range(n)]
    output=unpack(v['ranges']['output'],proof['output']['words'],d);real=[1]*v['count']+[0]*(n-v['count'])
    def item(name,index,m,ids,terms,rows):
        return name,dict(id=16384*p.identity+512+index,m=m,k=0,ids=ids,terms=[(r.sc.scalar(x,d),factors) for x,factors in terms]),[[r.sc.scalar(x,d) for x in row] for row in rows]
    # Complete signed8 consumption gives V=raw-256*sign; every side is <p/2.
    result=[item('Restoration',0,v['a'],list(range(base+16,base+21)),[(1,[0]),(256,[1,3]),(-1,[1,2]),(-v['S'],[4])],[output,broadcast,raw,sign[:n],real])]
    if v['dynamic']:
        flags=unpack(v['ranges']['nonzero'],proof['nonzero']['words'],d);pred=unpack(v['ranges']['predecessor'],proof['predecessor']['words'],d);zero=[0]*nr
        # The two halves bind s=k+n and s*(1-n)=0 under complete n/k ranges.
        result.append(item('ScalePredicates',1,v['ar']+1,list(range(base+21,base+25)),[(1,[0]),(-1,[1]),(-1,[2]),(-1,[0,3])],[scales+scales,pred+zero,flags+zero,zero+flags]))
        mag=unpack(v['ranges']['magnitude'],proof['magnitude']['words'],d);active=[flags[i//p.schema.width] if i<v['count'] else 0 for i in range(n)]
        result.append(item('ZeroScaleCodes',2,v['a'],[base+25,base+26],[(1,[0]),(-1,[0,1])],[mag,active]))
    return result


def bound(v,expected,proof):
    return expected+[proof['roots'][name] for name in v['aux']]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==3+len(v['aux']) and type(states) is list and len(states)==len(v['names']) and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,codes,scales,d):
    v=derive(p,d);w=witness(p,codes,scales);return dict(source=ss.prove(v['signed'],codes,d),**{name:r.prove(child,w[name],d) for name,child in v['ranges'].items()})


def assemble(p,pairs,d):
    """Producer only; supplied child states never authorize verification."""
    v=derive(p,d);proof={name:pairs[name][0] for name in v['names']};proof['roots']={name:r.source_root(v['ranges'][name],proof[name]['words']) for name in v['aux']}
    t=transcript(v,bound(v,roots(p,proof),proof),[pairs[name][1] for name in v['names']],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,codes,scales,d):
    return assemble(p,prepare(p,codes,scales,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(v['names'])|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])==set(v['aux']),'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()) and type(proof['zero']) is list and len(proof['zero'])==(3 if v['dynamic'] else 1),'ProofShape')
    if not v['dynamic']:need(expected[1]==r.root(p.scale_source,scale_words(p,v,proof)),'Scale:CommitmentMismatch')
    children=[]
    try:children.append(ss.verify(v['signed'],[expected[0],proof['roots']['magnitude']],proof['source'],d))
    except ValueError as error:raise ValueError('Source:'+str(error)) from None
    for name,child in v['ranges'].items():
        try:
            target=expected[1] if name=='scale' else proof['roots'][name];children.append(r.verify(child,target,proof[name],d))
            if name=='output':need(r.root(p.output,full_output(v,proof[name]['words']))==expected[2],'CommitmentMismatch')
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(v,bound(v,expected,proof),[x['state'] for x in children],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==len(i['ids']) and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(x) is tuple and len(x)==d and all(type(y) is int and 0<=y<r.sc.P for y in x) for row in part['rounds']+part['final'] for x in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    inherited=children[0]['account'];accounts=[x['account'] for x in children[1:]]
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),account=dict(identities=inherited['identities']+[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=inherited['lookup_reduction_numerator']+sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=inherited['range_reduction_numerator']+sum(x['range_reduction_numerator'] for x in accounts)+sum(x['numerator'] for x in records),denominator=r.sc.P**d))
