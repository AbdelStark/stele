"""Draft RFC-0004 A3/A6: streamed complete global attention offsets.

O(B*N) byte work, O(N*d+B) parent storage plus one complete child proof and
B*8N temporary bytes. Child/caller/codec peaks are additional; no native PCS.
"""
from collections import Counter
from dataclasses import dataclass
import struct
import tempfile
from flint import nmod_mat
import attention_normalization_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-global-offset/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    identity: int
    sources: tuple
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<42 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    B=(p.schema.length+1023)//1024;a=(p.schema.width-1).bit_length();n=1<<a;bb=(B-1).bit_length();base=(1<<63)+(1<<20)*p.identity
    need(type(p.sources) is tuple and len(p.sources)==B,'Spec');ids=p.sources+(p.output,)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<20) for x in ids) and len(set(ids))==len(ids),'Spec')
    caps=[2*min(1024,p.schema.length-1024*b)*constants['probability_max']*constants['restored_max'] if p.schema.accumulation=='exact' else 2*constants['rounded_block_max'] for b in range(B)]
    carry_caps=[];incoming=0
    for k in range(8):incoming=(incoming+sum(min(255,x>>(8*k)) for x in caps))//256;carry_caps.append(incoming)
    need(sum(caps)==2*constants['total_max'] and sum(caps)<1<<64 and carry_caps[-1]==0 and max(carry_caps)<=B-1 and 2*(256*B-1)<r.sc.P,'FieldBound')
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQII',1,d,p.repetitions,p.identity,B,len(encoded))+encoded+b''.join(struct.pack('<Q',x) for x in ids)
    return dict(B=B,a=a,n=n,bb=bb,base=base,caps=caps,carry_caps=carry_caps,raw=raw)


def range_spec(p,v,index):
    need(type(index) is int and 0<=index<v['B']+3,'Spec');n=v['n'];w=p.schema.width
    if index<v['B']:offset=1+index;source=index;caps=(v['caps'][index],)*w
    elif index==v['B']:offset=1025;source=1024;caps=(sum(v['caps']),)*w
    else:
        g=index-v['B']-1;offset=1026+g;source=1025+g;caps=tuple(x for cap in v['carry_caps'][4*g:4*g+4] for x in [cap]*w+[0]*(n-w))
    return r.Spec(16384*p.identity+offset,v['base']+(1<<18)+source,caps,p.repetitions)


def full_words(v,words):
    need(type(words) is list and len(words)<=8*v['n'],'OpeningShape');return words+[0]*(8*v['n']-len(words))


def whole_values(plan,words):
    _,_,n,width,_,_=r.derive(plan,4);r.vector(words,n*width)
    return [sum(words[k*n+j]<<(8*k) for k in range(width)) for j in range(n)]


def final_values(p,v,columns):
    """Producer arithmetic; the verifier uses ranges and the projected equation."""
    n=v['n'];need(type(columns) is list and len(columns)==8*n,'Input');output=[0]*n;incoming=[0]*n;carry=[]
    for k in range(8):
        for j in range(n):
            incoming[j],byte=divmod(columns[k*n+j]+incoming[j],256);output[j]+=byte<<(8*k)
        carry.extend(incoming)
    return output[:p.schema.width],[carry[:4*n],carry[4*n:]]


def transcript(v,expected,roots,states,d):
    need(all(type(xs) is list and len(xs)==size and all(type(x) is bytes and len(x)==32 for x in xs) for xs,size in ((expected,v['B']+1),(roots,v['B']+3),(states,v['B']+3))),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(expected+roots+states),d)


def project(words,weights,d):
    # Bytes multiply extension coefficients linearly; no extension products here.
    row=nmod_mat(1,len(words),[x%r.sc.P for x in words],r.sc.P)*weights
    return tuple(int(row[0,j]) for j in range(d))


def replay(p,v,expected,spool,weights,d):
    spool.seek(0);values=[];size=8*v['n']
    for b,identity in enumerate(p.sources):
        raw=spool.read(size);need(len(raw)==size,'SpoolShape');words=list(raw)
        need(r.root(identity,words)==expected[b],'Block:'+str(b)+':CommitmentMismatch');values.append(project(words,weights,d))
    need(spool.read(1)==b'','SpoolShape');return values+[r.sc.scalar(0,d)]*((1<<v['bb'])-v['B'])


def parent(p,v,expected,roots,states,tail,spool,d):
    t=transcript(v,expected,roots,states,d);point=[r.sc.challenge(t) for _ in range(v['a']+3)];weights=r.scalar.eq_weights(point,d)
    matrix=nmod_mat(8*v['n'],d,[x for value in weights for x in value],r.sc.P);del weights
    output=full_words(v,tail['output']['words']);carry=[x for g in range(2) for x in whole_values(range_spec(p,v,v['B']+1+g),tail['carry'][g]['words'])]
    previous=[0]*v['n']+carry[:-v['n']];target=project([y+256*co-ci for y,co,ci in zip(output,carry,previous)],matrix,d)
    values=replay(p,v,expected,spool,matrix,d)
    instance=dict(id=65536*p.identity+8192,m=v['bb'],ids=[v['base']+(1<<19)+1],terms=[(r.sc.scalar(1,d),[0])],sum=target)
    return t,instance,[values]


def iterator(values):
    try:return iter(values)
    except TypeError:raise ValueError('StreamShape') from None


def prove(p,blocks,d):
    """Yield canonical records; the generator return value is the final state."""
    v=derive(p,d);blocks=iterator(blocks);expected=[];roots=[];states=[];columns=[0]*(8*v['n']);end=object()
    with tempfile.TemporaryFile() as spool:
        for b,identity in enumerate(p.sources):
            values=next(blocks,end);need(values is not end,'StreamShape');plan=range_spec(p,v,b);proof,state=r.prove(plan,values,d);words=full_words(v,proof['words'])
            expected.append(r.root(identity,words));roots.append(r.source_root(plan,proof['words']));states.append(state);spool.write(bytes(words))
            for j,x in enumerate(words):columns[j]+=x
            yield dict(block=b,range=proof)
            del proof,words,values
        need(next(blocks,end) is end,'StreamShape');output,carries=final_values(p,v,columns);del columns
        children=[]
        for j,values in enumerate([output]+carries,v['B']):
            plan=range_spec(p,v,j);proof,state=r.prove(plan,values,d);children.append(proof);roots.append(r.source_root(plan,proof['words']));states.append(state)
        tail=dict(output=children[0],carry=children[1:]);expected.append(r.root(p.output,full_words(v,children[0]['words'])))
        t,i,tables=parent(p,v,expected,roots,states,tail,spool,d);tail['sum'],_=r.sc.prove(t,i,tables);yield tail
        return t.state


def sum_shape(proof,m,d):
    need(type(proof) is dict and set(proof)=={'rounds','final'} and type(proof['rounds']) is list and len(proof['rounds'])==m and all(type(row) is list and len(row)==2 for row in proof['rounds']) and type(proof['final']) is list and len(proof['final'])==1,'ProofShape')
    need(all(type(value) is tuple and len(value)==d and all(type(x) is int and 0<=x<r.sc.P for x in value) for row in proof['rounds']+[proof['final']] for value in row),'NoncanonicalField')


def verify(p,expected,records,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==v['B']+1 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');expected=expected.copy();records=iterator(records);roots=[];states=[];draws=Counter()
    account=dict(identities=[],lookup_reduction_numerator=0,range_reduction_numerator=0,projection_identity_numerator=v['a']+3,sum_reduction_numerator=v['bb'],denominator=r.sc.P**d)
    def consume(index,proof):
        plan=range_spec(p,v,index);need(type(proof) is dict and 'words' in proof,'ProofShape');root=r.source_root(plan,proof['words']);result=r.verify(plan,root,proof,d)
        roots.append(root);states.append(result['state']);draws.update(result['draws']);a=result['account'];account['identities'].append((a['identity_numerator'],a['identity_power']))
        for key in ('lookup_reduction_numerator','range_reduction_numerator'):account[key]+=a[key]
    end=object()
    with tempfile.TemporaryFile() as spool:
        for b,identity in enumerate(p.sources):
            record=next(records,end);need(type(record) is dict and set(record)=={'block','range'} and type(record['block']) is int and record['block']==b,'StreamShape')
            try:consume(b,record['range'])
            except ValueError as error:raise ValueError('Block:'+str(b)+':Range:'+str(error)) from None
            words=full_words(v,record['range']['words']);need(r.root(identity,words)==expected[b],'Block:'+str(b)+':CommitmentMismatch');spool.write(bytes(words));del record,words
        tail=next(records,end);need(type(tail) is dict and set(tail)=={'output','carry','sum'} and type(tail['carry']) is list and len(tail['carry'])==2,'StreamShape');need(next(records,end) is end,'StreamShape')
        for j,child in enumerate([tail['output']]+tail['carry'],v['B']):
            try:consume(j,child)
            except ValueError as error:raise ValueError(('Output' if j==v['B'] else 'Carry:'+str(j-v['B']-1))+':Range:'+str(error)) from None
        need(r.root(p.output,full_words(v,tail['output']['words']))==expected[-1],'Output:CommitmentMismatch');sum_shape(tail['sum'],v['bb'],d)
        t,i,tables=parent(p,v,expected,roots,states,tail,spool,d)
        try:result=r.sc.verify_public(t,i,tail['sum'],tables)
        except ValueError as error:raise ValueError('Sum:'+str(error)) from None
        return dict(state=t.state,account=account,draws=dict(t.draws),child_draws=dict(draws),claims=result['claims'],sc=result['sc'])
