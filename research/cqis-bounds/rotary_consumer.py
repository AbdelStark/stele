"""Draft RFC-0004 A3/A6/A7: complete canonical rotary row consumers.

O(heads*width) views/ranges and four A3s; canonical coefficient generation and
full public MLE consumers remain reference costs, not native fast verification.
"""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import struct
import sys
import rotary_bounds as rotary
import signed_source as signed
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-checkpoint'))
import rope

r=signed.r
need=r.need
PREFIX=b'stele/research/q26/rotary-consumer/v1\0'
ROLES=('source','output','magnitude','sign','quotient','remainder')
CHILDREN=('input','output','magnitude','sign','predecessor','remainder')


@dataclass(frozen=True)
class Spec:
    schema: rotary.Spec
    rotation: rope.Parameters | None
    position: int
    identity: int
    source: int
    output: int
    magnitude: int
    sign: int
    quotient: int
    remainder: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');bounds=rotary.derive(p.schema);s=p.schema
    need(type(p.position) is int and 0<=p.position<s.length,'Position')
    need(type(p.identity) is int and 0<=p.identity<1<<48 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    descriptor=b''
    if s.rotary:
        need(type(p.rotation) is rope.Parameters,'Spec');p.rotation.__post_init__()
        need((p.rotation.width,p.rotation.length,p.rotation.layout)==(s.rotary,s.length,s.layout),'Spec');descriptor=rope.encode(p.rotation)
    else:need(p.rotation is None,'Spec')
    count=bounds['row_width'];a=(count-1).bit_length();n=1<<a;base=(1<<63)+(1<<14)*p.identity;ids=tuple(getattr(p,name) for name in ROLES)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<14) for x in ids) and len(set(ids))==6,'Spec')
    sources=dict(input=signed.Spec(32*p.identity+1,p.source,base+1,16,count,p.repetitions),output=signed.Spec(32*p.identity+2,p.output,p.quotient,16,count,p.repetitions))
    for child in sources.values():signed.derive(child,d)
    caps=(bounds['numerator_max'],1,bounds['numerator_max'],16383);names=('magnitude','sign','predecessor','remainder');source_ids=(p.magnitude,p.sign,base+2,p.remainder)
    ranges={name:r.Spec(256*p.identity+index,source,(cap,)*count,p.repetitions) for index,(name,source,cap) in enumerate(zip(names,source_ids,caps),1)}
    need([r.derive(child,d)[3] for child in ranges.values()]==[4,1,4,2],'Capacity')
    need(2*max(bounds['biased_max'],bounds['numerator_max']+1,bounds['division_max'])<r.sc.P,'FieldBound')
    raw=PREFIX+struct.pack('<BBB'+'Q'*7+'I',1,d,p.repetitions,p.identity,*ids,p.position)+rotary.encode(s)+struct.pack('<H',len(descriptor))+descriptor
    return dict(**sources,ranges=ranges,bounds=bounds,count=count,a=a,n=n,base=base,raw=raw,descriptor=descriptor)


@lru_cache(maxsize=16,typed=True)
def coefficient_row(descriptor,position):
    """Immutable public definition; callers validate metadata before cache access."""
    definition=rope.decode(descriptor);row=[]
    for j in range(definition.width//2):
        entry=rope.certify(definition,position,j);co,si=entry['cos'],entry['sin']
        need(abs(co)<=16384 and abs(si)<=16384 and abs(co)+abs(si)<=23171,'CoefficientEnvelope');row.append((co,si))
    return tuple(row)


def coefficients(p):
    v=derive(p,4);return coefficient_row(v['descriptor'],p.position) if p.schema.rotary else ()


def source_views(p,values):
    v=derive(p,4);count=v['count'];need(type(values) is list and len(values)==count,'Input');coeff=coefficients(p)
    x0=values.copy();x1=values.copy();c0=[16384]*count;c1=[0]*count
    for left,right,j in rotary.pairs(p.schema):
        co,si=coeff[j];x0[left]=x0[right]=values[left];x1[left]=x1[right]=values[right];c0[left],c1[left]=co,-si;c0[right],c1[right]=si,co
    return [row+[0]*(v['n']-count) for row in (x0,c0,x1,c1)]


def witness(p,xs):
    v=derive(p,4);need(type(xs) is list and len(xs)==v['count'] and all(type(x) is int and -32768<=x<=32767 for x in xs),'Input')
    x0,c0,x1,c1=source_views(p,xs);nums=[x*co+y*si for x,co,y,si in zip(x0,c0,x1,c1)][:v['count']];ms=list(map(abs,nums));ss=[int(x<0) for x in nums];qr=[divmod(m+8192,16384) for m in ms];qs=[q for q,_ in qr];rs=[rem for _,rem in qr];zs=[(1-2*s)*q for s,q in zip(ss,qs)]
    need(all(-32768<=z<=32767 for z in zs),'OutputRange')
    return dict(numerator=nums,magnitude=ms,sign=ss,predecessor=[m-s for m,s in zip(ms,ss)],quotient=qs,remainder=rs,output=zs)


def roots(p,proof):
    v=derive(p,4);rows=(proof['input']['ranges'][0]['words'],proof['output']['ranges'][0]['words'],proof['magnitude']['words'],proof['sign']['words'],proof['output']['ranges'][1]['words'],proof['remainder']['words'])
    for row,width in zip(rows,(2,2,4,1,2,2)):r.vector(row,width*v['n'])
    return [r.root(getattr(p,name),row) for name,row in zip(ROLES,rows)]


def expected_roots(p,xs):
    v=derive(p,4);w=witness(p,xs);rows=([x%65536 for x in xs],[z%65536 for z in w['output']],w['magnitude'],w['sign'],w['quotient'],w['remainder'])
    return [r.root(getattr(p,name),[x>>(8*k)&255 for k in range(width) for x in values+[0]*(v['n']-v['count'])]) for name,values,width in zip(ROLES,rows,(2,2,4,1,2,2))]


def parts(p,proof,d):
    v=derive(p,d);n=v['n'];raw=proof['input']['ranges'][0]['words'];flags=proof['input']['ranges'][2]['words'];q=proof['output']['ranges'][1]['words'];sz=proof['output']['ranges'][2]['words'];M=proof['magnitude']['words'];S=proof['sign']['words'];G=proof['predecessor']['words'];R=proof['remainder']['words']
    for row,width in ((raw,2),(flags,2),(q,2),(sz,2),(M,4),(S,1),(G,4),(R,2)):r.vector(row,width*n)
    # Complete signed/range children precede use of these small whole values.
    xs=[raw[i]+256*raw[n+i]-65536*flags[i] for i in range(v['count'])];source=source_views(p,xs)
    whole=lambda row,width:[sum(row[k*n+i]<<(8*k) for k in range(width)) for i in range(n)]
    ms=whole(M,4);gs=whole(G,4);qs=whole(q,2);rs=whole(R,2);bias=[8192 if i<v['count'] else 0 for i in range(n)]
    def item(name,index,start,terms,rows):
        return name,dict(id=1024*p.identity+128+index,m=v['a'],k=0,ids=list(range(v['base']+start,v['base']+start+len(rows))),terms=[(r.sc.scalar(value,d),factors) for value,factors in terms]),[[r.sc.scalar(x,d) for x in row] for row in rows]
    return [item('Numerator',0,16,[(1,[0,1]),(1,[2,3]),(-1,[4]),(2,[5,4])],source+[ms,S]),
            item('CanonicalZero',1,22,[(1,[0]),(-1,[1]),(-1,[2])],[ms,S,gs]),
            item('Rounding',2,25,[(1,[0]),(1,[1]),(-16384,[2]),(-1,[3])],[ms,bias,qs,rs]),
            item('SignedOutput',3,29,[(1,[0,1]),(-1,[0,2])],[qs,S,sz[:n]])]


def transcript(v,bound,states,d):
    need(type(bound) is list and len(bound)==8 and type(states) is list and len(states)==6 and all(type(x) is bytes and len(x)==32 for x in bound+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(bound+states),d)


def prepare(p,xs,d):
    v=derive(p,d);w=witness(p,xs)
    return dict(input=signed.prove(v['input'],xs,d),output=signed.prove(v['output'],w['output'],d),**{name:r.prove(child,w[name],d) for name,child in v['ranges'].items()})


def assemble(p,pairs,d):
    """Producer only; supplied states and public views confer no acceptance."""
    v=derive(p,d);proof={name:pairs[name][0] for name in CHILDREN};proof['roots']=dict(input_magnitude=r.root(v['base']+1,proof['input']['ranges'][1]['words']),predecessor=r.source_root(v['ranges']['predecessor'],proof['predecessor']['words']))
    t=transcript(v,roots(p,proof)+[proof['roots'][name] for name in ('input_magnitude','predecessor')],[pairs[name][1] for name in CHILDREN],d);proof['zero']=[r.zero_prove(t,i,tables) for _,i,tables in parts(p,proof,d)]
    return proof,t.state


def prove(p,xs,d):
    return assemble(p,prepare(p,xs,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==6 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(CHILDREN)|{'roots','zero'} and type(proof['roots']) is dict and set(proof['roots'])=={'input_magnitude','predecessor'} and type(proof['zero']) is list and len(proof['zero'])==4,'ProofShape')
    need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,targets in (('input',[expected[0],proof['roots']['input_magnitude']]),('output',[expected[1],expected[4]])):
        try:children.append(signed.verify(v[name],targets,proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    for (name,child),target in zip(v['ranges'].items(),(expected[2],expected[3],proof['roots']['predecessor'],expected[5])):
        try:children.append(r.verify(child,target,proof[name],d))
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    t=transcript(v,expected+[proof['roots'][name] for name in ('input_magnitude','predecessor')],[child['state'] for child in children],d);records=[];claims=[]
    for (name,i,tables),part in zip(parts(p,proof,d),proof['zero']):
        need(type(part) is dict and set(part)=={'skip','rounds','final'} and type(part['skip']) is list and not part['skip'] and type(part['rounds']) is list and len(part['rounds'])==i['m'] and all(type(row) is list and len(row)==r.sc.degree(i)+1 for row in part['rounds']) and type(part['final']) is list and len(part['final'])==len(i['ids']) and all(type(row) is list and len(row)==1 for row in part['final']),'ProofShape')
        need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in part['rounds']+part['final'] for value in row),'NoncanonicalField')
        try:receipt,_=r.zc.verify(t,i,part,tables)
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
        records.extend(receipt['sc']);claims.extend(receipt['claims'])
    sources=[child['account'] for child in children[:2]];ranges=[child['account'] for child in children[2:]]
    account=dict(identities=sum((item['identities'] for item in sources),[])+[(item['identity_numerator'],item['identity_power']) for item in ranges],lookup_reduction_numerator=sum(item['lookup_reduction_numerator'] for item in sources+ranges),range_reduction_numerator=sum(item['range_reduction_numerator'] for item in sources+ranges)+sum(row['numerator'] for row in records),denominator=r.sc.P**d)
    return dict(state=t.state,children=children,sc=records,claims=claims,draws=dict(t.draws),account=account)
