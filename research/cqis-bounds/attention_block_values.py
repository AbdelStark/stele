"""Draft RFC-0004 A3/A6: complete signed sources and one restored-block A1.

Linear digit projection; O(width*d+rows*d+groups) parent state, one live child
and five spooled bytes per actual value. Caller/codec peaks are additional.
"""
from collections import Counter
from dataclasses import dataclass
import struct
import tempfile
import attention_sum_bounds as bounds
import signed_source as ss
from attention_value_projection import EqProjector

r=ss.r
need=r.need
PREFIX=b'stele/research/q26/attention-block-values/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    block: int
    identity: int
    source: int
    scale_source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');cert=bounds.constants(p.schema)
    need(type(p.block) is int and 0<=p.block<(p.schema.length+1023)//1024,'Spec');rows=min(1024,p.schema.length-1024*p.block);width=p.schema.width
    need(type(p.identity) is int and 0<=p.identity<1<<37 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<25)*p.identity;external=(p.source,p.scale_source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<25) for x in external) and len(set(external))==3,'Spec')
    count=rows*width;a=(count-1).bit_length();ar=(rows-1).bit_length();group_rows=16384//width;sizes=tuple(min(group_rows,rows-j)*width for j in range(0,rows,group_rows));dynamic=p.schema.value_mode=='dynamic'
    S=cert['restored_max'];bound=max(2*S+256*cert['scale_max'],S+255*cert['scale_max']);need(2*bound<r.sc.P,'FieldBound')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQQIII',1,d,p.repetitions,p.identity,*external,p.block,rows,len(encoded))+encoded
    return dict(rows=rows,width=width,count=count,a=a,ar=ar,n=1<<a,nr=1<<ar,group_rows=group_rows,sizes=sizes,groups=len(sizes),children=3*len(sizes)+3*dynamic,common=3*dynamic,base=base,dynamic=dynamic,cap=cert['code_max'],S=S,bound=bound,raw=raw)


def group_specs(p,v,g):
    need(type(g) is int and 0<=g<v['groups'],'Spec');base=v['base']+(1<<14)*g;count=v['sizes'][g]
    return (ss.Spec(65536*p.identity+32*g+1,base+1,base+2,8,count,p.repetitions),r.Spec(524288*p.identity+256*g+65,base+2,(v['cap'],)*count,p.repetitions),r.Spec(524288*p.identity+256*g+66,base+3,(2*v['S'],)*count,p.repetitions))


def common_specs(p,v):
    if not v['dynamic']:return []
    return [r.Spec(524288*p.identity+262144+j+1,source,(cap,)*v['rows'],p.repetitions) for j,(source,cap) in enumerate(((p.scale_source,259),(v['base']+(1<<24)+1,1),(v['base']+(1<<24)+2,258)))]


def child_spec(p,v,index):
    need(type(index) is int and 0<=index<v['children'],'Spec')
    if index<v['common']:return ('scale','nonzero','predecessor')[index],None,common_specs(p,v)[index]
    g,role=divmod(index-v['common'],3);return ('source','magnitude','output')[role],g,group_specs(p,v,g)[role]


def planes(values,n,width):
    need(len(values)<=n,'OpeningShape');return [x>>(8*k)&255 for k in range(width) for x in values+[0]*(n-len(values))]


def unpack(plan,words):
    _,_,n,width,_,_=r.derive(plan,4);r.vector(words,n*width);return [sum(words[k*n+j]<<(8*k) for k in range(width)) for j in range(n)]


def initial(p,v):
    return dict(scale=[] if v['dynamic'] else [p.schema.scale]*v['rows']+[0]*(v['nr']-v['rows']))


def values(p,v,g,codes,scales):
    need(type(codes) is list and len(codes)==v['sizes'][g] and all(type(x) is int and abs(x)<=v['cap'] for x in codes),'Input');start=g*v['group_rows']
    need(all(scales[start+i//v['width']]!=0 or code==0 for i,code in enumerate(codes)),'Input')
    return [v['S']+code*scales[start+i//v['width']] for i,code in enumerate(codes)]


def write_group(spool,raw,output):
    need(len(raw)==len(output),'SpoolShape');spool.write(b''.join(struct.pack('<BI',x,y) for x,y in zip(raw,output)))


def external_roots(p,v,scales,spool):
    spool.seek(0,2);need(spool.tell()==5*v['count'],'SpoolShape');merkle=r.lu.merkle
    def payloads(offsets):
        for k in offsets:
            spool.seek(0)
            for size in v['sizes']:
                raw=spool.read(5*size);need(len(raw)==5*size,'SpoolShape')
                for byte in raw[k::5]:yield struct.pack('<I',byte)
            for _ in range(v['n']-v['count']):yield bytes(4)
    return [merkle.root(merkle.Tree(0,p.source,v['n'],4),payloads((0,))),r.root(p.scale_source,planes(scales,v['nr'],2)),merkle.root(merkle.Tree(0,p.output,4*v['n'],4),payloads((1,2,3,4)))]


def child_roots(p,v,index,proof,d):
    role,_,plan=child_spec(p,v,index);need(type(proof) is dict,'ProofShape')
    if role=='source':
        need(type(proof.get('ranges')) is list and len(proof['ranges'])==3 and all(type(x) is dict and 'words' in x for x in proof['ranges']),'ProofShape')
        return [r.source_root(child,part['words']) for child,part in zip(ss.derive(plan,d)['ranges'][:2],proof['ranges'][:2])]
    need('words' in proof,'ProofShape');return [r.source_root(plan,proof['words'])]


def retain(p,v,index,proof,roots,local,spool):
    role,g,plan=child_spec(p,v,index)
    if role=='source':local['raw']=proof['ranges'][0]['words'][:plan.count];local['magnitude_root']=roots[1]
    elif role=='magnitude':need(roots[0]==local['magnitude_root'],'Magnitude:'+str(g)+':CommitmentMismatch')
    elif role=='output':write_group(spool,local.pop('raw'),unpack(plan,proof['words'])[:v['sizes'][g]]);del local['magnitude_root']
    else:local[role]=unpack(plan,proof['words'])


def context(v,expected,roots,states,d):
    need(len(expected)==3 and len(roots)==v['children']+v['groups'] and len(states)==v['children'] and all(type(x) is bytes and len(x)==32 for x in expected+roots+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(expected+roots+states),d)


def predicates(p,v,local,d):
    zero=[0]*v['nr'];scales=local['scale'];flags=local['nonzero'];pred=local['predecessor'];base=v['base']+(1<<24)
    instance=dict(id=2097152*p.identity+1048576+64,m=v['ar']+1,k=0,ids=list(range(base+512,base+516)),terms=[(r.sc.scalar(c,d),factors) for c,factors in ((1,[0]),(-1,[1]),(-1,[2]),(-1,[0,3]))])
    return instance,[[r.sc.scalar(x,d) for x in row] for row in (scales+scales,pred+zero,flags+zero,zero+flags)]


def parent(p,v,t,roots,local,spool,d):
    sc=r.sc;point=[sc.challenge(t) for _ in range(v['a'])];eta=sc.challenge(t) if v['dynamic'] else None;projector=EqProjector(point,d);B=[];M=[];target=sc.scalar(0,d);spool.seek(0)
    for g,size in enumerate(v['sizes']):
        data=spool.read(5*size);need(len(data)==5*size,'SpoolShape');pairs=list(struct.iter_unpack('<BI',data));raw=[x for x,_ in pairs];output=[y for _,y in pairs];magnitude=[x if x<128 else 256-x for x in raw];signed,mag,up=group_specs(p,v,g);n=1<<(size-1).bit_length();width=r.derive(up,d)[3];at=v['common']+4*g
        # Check public-zero high bytes before compact re-encoding can discard them.
        need(all(x<1<<(8*width) for x in output) and [r.root(signed.source,planes(raw,n,1)),r.root(mag.source,planes(magnitude,n,1)),r.source_root(up,planes(output,n,width))]==[roots[at],roots[at+1],roots[at+3]],'Replay:'+str(g)+':CommitmentMismatch')
        for start in range(0,size,v['width']):
            stop=start+v['width'];b,m,u=projector.row([[256*(x>>7)-x for x in raw[start:stop]],magnitude[start:stop],[v['S']-x for x in output[start:stop]]]);B.append(b);M.append(m);target=sc.add(target,u)
    need(spool.read(1)==b'' and projector.at==v['count'],'SpoolShape');padding=[sc.scalar(0,d)]*(v['nr']-v['rows']);tables=[[sc.scalar(x,d) for x in local['scale']],B+padding];terms=[(sc.scalar(1,d),[0,1])]
    if v['dynamic']:tables.extend([[sc.scalar(1-x,d) for x in local['nonzero'][:v['rows']]]+padding,M+padding]);terms.append((eta,[2,3]))
    base=v['base']+(1<<24)+1024;instance=dict(id=2097152*p.identity+1048576+65,m=v['ar'],ids=list(range(base,base+len(tables))),terms=terms,sum=target)
    return instance,tables


def iterator(records):
    try:return iter(records)
    except TypeError:raise ValueError('StreamShape') from None


def prove(p,scales,groups,d):
    v=derive(p,d);need(type(scales) is list and len(scales)==v['rows'] and all(type(s) is int and (0<=s<=259 if v['dynamic'] else s==p.schema.scale) for s in scales),'Input');scales=scales.copy();groups=iterator(groups);end=object();roots=[];states=[];local=initial(p,v)
    with tempfile.TemporaryFile() as spool:
        for index in range(v['children']):
            role,g,plan=child_spec(p,v,index)
            if g is None:xs={'scale':scales,'nonzero':[int(s!=0) for s in scales],'predecessor':[max(s-1,0) for s in scales]}[role]
            elif role=='source':
                codes=next(groups,end);need(codes is not end,'StreamShape');us=values(p,v,g,codes,scales);xs=codes
            elif role=='magnitude':xs=list(map(abs,codes))
            else:xs=us
            proof,state=ss.prove(plan,xs,d) if role=='source' else r.prove(plan,xs,d);part=child_roots(p,v,index,proof,d);retain(p,v,index,proof,part,local,spool);roots.extend(part);states.append(state)
            yield dict(child=index,proof=proof)
            del proof,xs
            if role=='output':del codes,us
        need(next(groups,end) is end,'StreamShape');expected=external_roots(p,v,local['scale'],spool);t=context(v,expected,roots,states,d);predicate=None
        if v['dynamic']:
            instance,tables=predicates(p,v,local,d);predicate=r.zero_prove(t,instance,tables)
        instance,tables=parent(p,v,t,roots,local,spool,d);yield dict(predicates=predicate,sum=r.sc.prove(t,instance,tables)[0]);return t.state


def canonical(rows,d):
    need(all(type(x) is tuple and len(x)==d and all(type(y) is int and 0<=y<r.sc.P for y in x) for row in rows for x in row),'NoncanonicalField')


def verify(p,expected,records,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');expected=expected.copy();records=iterator(records);end=object();roots=[];states=[];local=initial(p,v);draws=Counter()
    account=dict(identities=[],lookup_reduction_numerator=0,range_reduction_numerator=0,restoration_identity_numerator=v['a']+v['dynamic'],restoration_reduction_numerator=2*v['ar'],denominator=r.sc.P**d)
    if not v['dynamic']:need(expected[1]==r.root(p.scale_source,planes(local['scale'],v['nr'],2)),'Scale:CommitmentMismatch')
    with tempfile.TemporaryFile() as spool:
        for index in range(v['children']):
            record=next(records,end);need(type(record) is dict and set(record)=={'child','proof'} and type(record['child']) is int and record['child']==index,'StreamShape');proof=record['proof'];role,g,plan=child_spec(p,v,index);part=child_roots(p,v,index,proof,d)
            try:result=ss.verify(plan,part,proof,d) if role=='source' else r.verify(plan,part[0],proof,d)
            except ValueError as error:raise ValueError(role.title()+(':'+str(g) if g is not None else '')+':'+str(error)) from None
            roots.extend(part);states.append(result['state']);draws.update(result['draws']);a=result['account']
            if role=='source':
                account['identities'].extend(a['identities'])
                for child in result['ranges']:draws.update(child['draws'])
            else:account['identities'].append((a['identity_numerator'],a['identity_power']))
            for key in ('lookup_reduction_numerator','range_reduction_numerator'):account[key]+=a[key]
            retain(p,v,index,proof,part,local,spool);del record,proof,result
        actual=external_roots(p,v,local['scale'],spool)
        for name,want,got in zip(('Source','Scale','Output'),expected,actual):need(want==got,name+':CommitmentMismatch')
        tail=next(records,end);need(type(tail) is dict and set(tail)=={'predicates','sum'} and next(records,end) is end,'StreamShape');t=context(v,expected,roots,states,d);predicate_claims=[]
        if v['dynamic']:
            i,tables=predicates(p,v,local,d);z=tail['predicates'];need(type(z) is dict and set(z)=={'skip','rounds','final'} and type(z['skip']) is list and not z['skip'] and type(z['rounds']) is list and len(z['rounds'])==i['m'] and all(type(row) is list and len(row)==3 for row in z['rounds']) and type(z['final']) is list and len(z['final'])==4 and all(type(row) is list and len(row)==1 for row in z['final']),'ProofShape');canonical(z['rounds']+z['final'],d)
            try:receipt,_=r.zc.verify(t,i,z,tables)
            except ValueError as error:raise ValueError('ScalePredicates:'+str(error)) from None
            account['range_reduction_numerator']+=sum(x['numerator'] for x in receipt['sc']);predicate_claims=receipt['claims']
        else:need(tail['predicates'] is None,'ProofShape')
        s=tail['sum'];need(type(s) is dict and set(s)=={'rounds','final'} and type(s['rounds']) is list and len(s['rounds'])==v['ar'] and all(type(row) is list and len(row)==3 for row in s['rounds']) and type(s['final']) is list and len(s['final'])==(4 if v['dynamic'] else 2),'ProofShape');canonical(s['rounds']+[s['final']],d)
        instance,tables=parent(p,v,t,roots,local,spool,d)
        try:receipt=r.sc.verify_public(t,instance,s,tables)
        except ValueError as error:raise ValueError('Restoration:'+str(error)) from None
        return dict(state=t.state,account=account,draws=dict(t.draws),child_draws=dict(draws),claims=receipt['claims'],predicate_claims=predicate_claims,sc=receipt['sc'])
