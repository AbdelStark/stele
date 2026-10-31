"""Draft RFC-0004 A3/A6: full-row attained maximum with one projected A1.

Linear byte work; one complete child, one group, bounded suffix weights and
28 temporary bytes per actual score. Caller/codec peaks are additional.
"""
from collections import Counter
from dataclasses import dataclass
import struct
import tempfile
from flint import nmod_mat
import attention_maximum as local_maximum

maximum=local_maximum.maximum
r=local_maximum.r
need=r.need
PREFIX=b'stele/research/q26/attention-global-maximum/v1\0'
ROLES=('source','offset','difference','gap','source_carry','difference_carry','first_carry')


@dataclass(frozen=True)
class Spec:
    schema: maximum.Spec
    position: int
    window: int
    start: int
    stop: int
    identity: int
    source: int
    maximum: int
    selection: int
    difference: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');bounds=maximum.derive(p.schema);L=p.schema.length
    need(type(p.position) is int and 0<=p.position<L,'Position');need(all(type(x) is int for x in (p.window,p.start,p.stop)) and 0<=p.window<=L and 0<=p.start<=p.position<p.stop<=L,'Mask')
    need(type(p.identity) is int and 0<=p.identity<1<<39 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec');base=(1<<63)+(1<<23)*p.identity;ids=(p.source,p.maximum,p.selection,p.difference)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<23) for x in ids) and len(set(ids))==4,'Spec');need(2*511<r.sc.P,'FieldBound')
    a=(L-1).bit_length();sizes=tuple(min(16384,L-j) for j in range(0,L,16384));raw=PREFIX+struct.pack('<BBBQQQQQIIII',1,d,p.repetitions,p.identity,*ids,p.position,p.window,p.start,p.stop)+maximum.encode(p.schema)
    return dict(bounds=bounds,a=a,n=1<<a,sizes=sizes,groups=len(sizes),children=1+7*len(sizes),base=base,raw=raw)


def allowed(p,j):
    return p.start<=j<p.stop and j<=p.position and (p.window==0 or p.position-j<p.window)


def selection(p,selected):
    need(type(selected) is int and 0<=selected<p.schema.length and allowed(p,selected),'Selection')


def range_spec(p,v,index):
    need(type(index) is int and 0<=index<v['children'],'Spec')
    if index==0:return r.Spec(131072*p.identity+65536+1,p.maximum,((1<<32)-1,),p.repetitions)
    g,role=divmod(index-1,7);size=v['sizes'][g];n=1<<(size-1).bit_length();start=g*16384
    if role==0:caps=((1<<32)-1,)*size
    elif role==1:caps=(v['bounds']['score_offset_max'],)*size
    elif role<4:caps=tuple(v['bounds']['delta_max']*allowed(p,start+j) for j in range(size))
    else:caps=((1,)*size+(0,)*(n-size))*4
    return r.Spec(131072*p.identity+1024*g+role+1,v['base']+65536*g+32768+role+1,caps,p.repetitions)


def iterator(records):
    try:return iter(records)
    except TypeError:raise ValueError('StreamShape') from None


def prefill(p,v,groups,spool):
    groups=iterator(groups);end=object();selected=None;best=None
    for g,size in enumerate(v['sizes']):
        xs=next(groups,end);need(type(xs) is list and len(xs)==size and all(type(x) is int and abs(x)<=p.schema.score_max for x in xs),'Input')
        for j,x in enumerate(xs):
            at=g*16384+j
            if allowed(p,at) and (best is None or x>best):best=x;selected=at
        spool.write(b''.join(struct.pack('<I',x%(1<<32))+bytes(24) for x in xs))
    need(next(groups,end) is end,'StreamShape');selection(p,selected);return selected,best%(1<<32)


def group_values(p,v,g,raw,maximum_raw,selected):
    size=v['sizes'][g];need(type(raw) is list and len(raw)==size and all(type(x) is int and 0<=x<1<<32 for x in raw),'Input');n=1<<(size-1).bit_length();S=p.schema.score_max;M=maximum_raw if maximum_raw<1<<31 else maximum_raw-(1<<32);xs=[x if x<1<<31 else x-(1<<32) for x in raw];mask=[allowed(p,g*16384+j) for j in range(size)];O=[x+S for x in xs];D=[M-x if bit else 0 for x,bit in zip(xs,mask)];prefix=[int(bit and g*16384+j<selected) for j,bit in enumerate(mask)];G=[x-y for x,y in zip(D,prefix)];pad=lambda row:row+[0]*(n-size)
    need(all(0<=x<=v['bounds']['delta_max'] for x in D) and min(G)>=0,'Domain')
    return [raw,O,D,G,local_maximum.carry_values(pad(raw),[S]*size+[0]*(n-size),n),local_maximum.carry_values(pad([x*bit for x,bit in zip(O,mask)]),pad(D),n),local_maximum.carry_values(pad(G),pad(prefix),n)]


def unpack(plan,words):
    _,_,n,width,_,_=r.derive(plan,4);r.vector(words,n*width);return [sum(words[k*n+j]<<(8*k) for k in range(width)) for j in range(n)]


def write_group(v,g,values,spool):
    size=v['sizes'][g];n=1<<(size-1).bit_length();need(type(values) is list and len(values)==7 and all(len(xs)==size for xs in values[:4]) and all(len(xs)==4*n for xs in values[4:]),'SpoolShape')
    data=b''.join(struct.pack('<IIII12B',*(xs[j] for xs in values[:4]),*(xs[k*n+j] for xs in values[4:] for k in range(4))) for j in range(size));spool.seek(28*16384*g);spool.write(data)


def retain(p,v,index,words,local,spool):
    if index==0:r.vector(words,4);local['maximum']=words.copy();return
    g,role=divmod(index-1,7);values=unpack(range_spec(p,v,index),words)
    if role==0:local['group']=[]
    local['group'].append(values[:v['sizes'][g]] if role<4 else values)
    if role==6:write_group(v,g,local.pop('group'),spool)


def external_roots(p,v,selected,maximum_words,spool):
    spool.seek(0,2);need(spool.tell()==28*p.schema.length,'SpoolShape');merkle=r.lu.merkle
    def payloads(offset):
        for k in range(4):
            spool.seek(0)
            for size in v['sizes']:
                data=spool.read(28*size);need(len(data)==28*size,'SpoolShape')
                for x in data[offset+k::28]:yield struct.pack('<I',x)
            for _ in range(v['n']-p.schema.length):yield bytes(4)
    return [merkle.root(merkle.Tree(0,p.source,4*v['n'],4),payloads(0)),r.root(p.maximum,maximum_words),r.root(p.selection,[selected]),merkle.root(merkle.Tree(0,p.difference,4*v['n'],4),payloads(8))]


def replay(p,v,g,data,roots,d):
    size=v['sizes'][g];n=1<<(size-1).bit_length();need(len(data)==28*size,'SpoolShape')
    for role in range(7):
        plan=range_spec(p,v,1+7*g+role);width=r.derive(plan,d)[3];offset=4*role
        # Every retained high byte must be zero before compact encoding drops it.
        need(role>=4 or not any(any(data[offset+k::28]) for k in range(width,4)),'Replay:'+str(g)+':CommitmentMismatch')
        words=[x for k in range(width if role<4 else 4) for x in list(data[offset+k::28])+[0]*(n-size)]
        need(r.source_root(plan,words)==roots[1+7*g+role],'Replay:'+str(g)+':CommitmentMismatch')


def project(p,v,g,data,selected,point,d,cache):
    size=v['sizes'][g];a=(size-1).bit_length();n=1<<a;depth=v['a']-a;need(len(data)==28*size and len(point)==v['a'],'ProjectionShape');sc=r.sc;prefix=sc.scalar(1,d)
    for j,x in enumerate(point[:depth]):prefix=sc.mul(prefix,x if (g*16384)>>(v['a']-j-1)&1 else sc.add(sc.scalar(1,d),sc.neg(x)))
    # This cache belongs to one sampled point, never to an untrusted source.
    if a not in cache:cache[a]=nmod_mat(n,d,[x for weight in r.scalar.eq_weights(point[depth:],d) for x in weight],sc.P)
    mask=[int(allowed(p,g*16384+j)) for j in range(size)];rows=[list(data[k::28])+[0]*(n-size) for k in range(28)]
    rows.extend([[x*bit for x,bit in zip(data[4+k::28],mask)]+[0]*(n-size) for k in range(4)])
    rows.extend([[1]*size+[0]*(n-size),mask+[0]*(n-size),[int(bit and g*16384+j<selected) for j,bit in enumerate(mask)]+[0]*(n-size)])
    matrix=nmod_mat(35,n,[x for row in rows for x in row],sc.P)*cache[a]
    return [sc.mul(prefix,tuple(int(matrix[j,k]) for k in range(d))) for j in range(35)]


def context(v,expected,roots,states,d):
    need(len(expected)==4 and len(roots)==len(states)==v['children'] and all(type(x) is bytes and len(x)==32 for x in expected+roots+states),'Root');return r.scalar.Transcript(v['raw']+b''.join(expected+roots+states),d)


def parent(p,v,t,roots,selected,maximum_words,spool,d):
    selection(p,selected);sc=r.sc;point=[sc.challenge(t) for _ in range(v['a'])];beta=sc.challenge(t);gamma=sc.challenge(t);total=[sc.scalar(0,d)]*35;cache={};chosen=None;spool.seek(0)
    for g,size in enumerate(v['sizes']):
        data=spool.read(28*size);replay(p,v,g,data,roots,d);total=[sc.add(x,y) for x,y in zip(total,project(p,v,g,data,selected,point,d,cache))]
        if g*16384<=selected<g*16384+size:at=28*(selected-g*16384);chosen=data[at:at+8]
    need(spool.read(1)==b'','SpoolShape');need(chosen[:4]==bytes(maximum_words),'Attainment');zero=sc.scalar(0,d);powers=[sc.scalar(1,d)]
    for _ in range(3):powers.append(sc.mul(powers[-1],gamma))
    tables=[total[:4],[sc.mul(total[32],sc.scalar(p.schema.score_max>>(8*k)&255,d)) for k in range(4)],[zero]+total[16:19],total[4:8],total[16:20],total[28:32],total[8:12],[zero]+total[20:23],[sc.scalar(x,d) for x in chosen[4:8]],total[20:24],total[12:16],[total[34],zero,zero,zero],[zero]+total[24:27],total[24:28],[sc.add(total[23],total[27]),zero,zero,zero],powers]
    b2=sc.mul(beta,beta);b3=sc.mul(b2,beta);terms=[]
    for coefficient,items in ((sc.scalar(1,d),((1,0),(1,1),(1,2),(-1,3),(-256,4))),(beta,((1,5),(1,6),(1,7),(-256,9))),(b2,((1,10),(1,11),(1,12),(-1,6),(-256,13))),(b3,((1,14),))):
        terms.extend((sc.mul(coefficient,sc.scalar(c,d)),[i,15]) for c,i in items)
    terms.append((sc.neg(sc.mul(beta,total[33])),[8,15]));base=v['base']+(1<<22)+1024
    return dict(id=524288*p.identity+262144+64,m=2,ids=list(range(base,base+16)),terms=terms,sum=zero),tables


def prove(p,groups,d):
    v=derive(p,d);roots=[];states=[];local={}
    with tempfile.TemporaryFile() as spool:
        selected,maximum_raw=prefill(p,v,groups,spool);yield dict(selected=selected)
        for index in range(v['children']):
            plan=range_spec(p,v,index)
            if index==0:values=[maximum_raw]
            else:
                g,role=divmod(index-1,7)
                if role==0:
                    spool.seek(28*16384*g);data=spool.read(28*v['sizes'][g]);raw=[struct.unpack_from('<I',data,28*j)[0] for j in range(v['sizes'][g])];inputs=group_values(p,v,g,raw,maximum_raw,selected);del data,raw
                values=inputs[role]
            proof,state=r.prove(plan,values,d);roots.append(r.source_root(plan,proof['words']));states.append(state);retain(p,v,index,proof['words'],local,spool);yield dict(range=index,proof=proof);del proof,values
            if index and role==6:del inputs
        expected=external_roots(p,v,selected,local['maximum'],spool);t=context(v,expected,roots,states,d);instance,tables=parent(p,v,t,roots,selected,local['maximum'],spool,d);yield dict(sum=r.sc.prove(t,instance,tables)[0]);return t.state


def verify(p,expected,records,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==4 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');expected=expected.copy();records=iterator(records);end=object();header=next(records,end);need(type(header) is dict and set(header)=={'selected'},'StreamShape');selected=header['selected'];selection(p,selected);need(r.root(p.selection,[selected])==expected[2],'Selection:CommitmentMismatch');roots=[];states=[];local={};draws=Counter();account=dict(identities=[],lookup_reduction_numerator=0,range_reduction_numerator=0,maximum_identity_numerator=v['a']+5,maximum_reduction_numerator=4,denominator=r.sc.P**d)
    with tempfile.TemporaryFile() as spool:
        for index in range(v['children']):
            record=next(records,end);need(type(record) is dict and set(record)=={'range','proof'} and type(record['range']) is int and record['range']==index,'StreamShape');proof=record['proof'];plan=range_spec(p,v,index);need(type(proof) is dict and 'words' in proof,'ProofShape');root=r.source_root(plan,proof['words'])
            try:result=r.verify(plan,expected[1] if index==0 else root,proof,d)
            except ValueError as error:raise ValueError('Range:'+str(index)+':'+str(error)) from None
            roots.append(root);states.append(result['state']);draws.update(result['draws']);a=result['account'];account['identities'].append((a['identity_numerator'],a['identity_power']))
            for key in ('lookup_reduction_numerator','range_reduction_numerator'):account[key]+=a[key]
            retain(p,v,index,proof['words'],local,spool);del record,proof,result
        actual=external_roots(p,v,selected,local['maximum'],spool)
        for name,want,got in zip(('Source','Maximum','Selection','Difference'),expected,actual):need(want==got,name+':CommitmentMismatch')
        tail=next(records,end);need(type(tail) is dict and set(tail)=={'sum'} and next(records,end) is end,'StreamShape');proof=tail['sum'];need(type(proof) is dict and set(proof)=={'rounds','final'} and type(proof['rounds']) is list and len(proof['rounds'])==2 and all(type(row) is list and len(row)==3 for row in proof['rounds']) and type(proof['final']) is list and len(proof['final'])==16,'ProofShape')
        need(all(type(x) is tuple and len(x)==d and all(type(y) is int and 0<=y<r.sc.P for y in x) for row in proof['rounds']+[proof['final']] for x in row),'NoncanonicalField');t=context(v,expected,roots,states,d);instance,tables=parent(p,v,t,roots,selected,local['maximum'],spool,d)
        try:receipt=r.sc.verify_public(t,instance,proof,tables)
        except ValueError as error:raise ValueError('Maximum:'+str(error)) from None
        return dict(state=t.state,account=account,draws=dict(t.draws),child_draws=dict(draws),claims=receipt['claims'],sc=receipt['sc'])
