"""Draft RFC-0004 A3/A6: one weighted sum over complete canonical block sources.

Linear digit work; one live range proof, O(width*K+rows*d+groups) parent data
and four temporary bytes per actual U. Caller/codec peaks are additional.
"""
from collections import Counter
from dataclasses import dataclass
import struct
import tempfile
from flint import nmod_mat
import attention_sum_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-block-offset/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    block: int
    allowed: tuple
    identity: int
    probability: int
    value_source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.block) is int and 0<=p.block<(p.schema.length+1023)//1024,'Spec');rows=min(1024,p.schema.length-1024*p.block);width=p.schema.width
    need(type(p.allowed) is tuple and len(p.allowed)==rows and all(type(x) is bool for x in p.allowed),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<42 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    base=(1<<63)+(1<<20)*p.identity;external=(p.probability,p.value_source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<20) for x in external) and len(set(external))==3,'Spec')
    cert=bounds.limbs.derive(bounds.limbs.Spec(rows,constants['probability_max'],2*constants['restored_max'],4));k=len(cert['result_caps'])
    need(k+1<=16 and 2*max(cert['lhs']+cert['rhs'])<r.sc.P,'FieldBound')
    ar=(rows-1).bit_length();ac=(width-1).bit_length();count=rows*width;n=1<<(count-1).bit_length();nr=1<<ar;nc=1<<ac
    group_rows=32768//width;sizes=tuple(min(group_rows,rows-j)*width for j in range(0,rows,group_rows));groups=len(sizes)
    size=max(1,(max(cert['carry_caps']).bit_length()+7)//8);wc=1<<(size-1).bit_length();cg=min(16,65536//nc,131072//(nc*wc));carry_groups=16//cg
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQQIII',1,d,p.repetitions,p.identity,*external,p.block,rows,len(encoded))+encoded+bytes(p.allowed)
    return dict(rows=rows,width=width,count=count,n=n,nr=nr,nc=nc,ar=ar,ac=ac,group_rows=group_rows,sizes=sizes,groups=groups,carry_group=cg,carry_groups=carry_groups,children=groups+2+carry_groups,base=base,raw=raw,constants=constants,cert=cert,k=k,la=len(cert['left_caps']),lb=len(cert['right_caps']))


def range_spec(p,v,index):
    need(type(index) is int and 0<=index<v['children'],'Spec');C=v['constants'];nc=v['nc']
    if index==0:offset=1;caps=tuple(C['probability_max']*bit for bit in p.allowed)
    elif index<=v['groups']:offset=index+1;caps=(2*C['restored_max'],)*v['sizes'][index-1]
    elif index==v['groups']+1:offset=514;caps=(2*v['rows']*C['probability_max']*C['restored_max'],)*v['width']
    else:
        g=index-v['groups']-2;offset=515+g
        caps=tuple(v['cert']['carry_caps'][k] if k<=v['k'] and j<v['width'] else 0 for k in range(g*v['carry_group'],(g+1)*v['carry_group']) for j in range(nc))
    return r.Spec(16384*p.identity+offset,v['base']+(1<<18)+offset,caps,p.repetitions)


def planes(values,n,width):
    need(len(values)<=n,'OpeningShape');return [x>>(8*k)&255 for k in range(width) for x in values+[0]*(n-len(values))]


def unpack(plan,words):
    _,_,n,width,_,_=r.derive(plan,4);r.vector(words,n*width);return [sum(words[k*n+j]<<(8*k) for k in range(width)) for j in range(n)]


def retain(p,v,index,words,spool,local):
    plan=range_spec(p,v,index);values=unpack(plan,words)
    if index==0:local['probability']=values
    elif index<=v['groups']:
        values=values[:len(plan.caps)];spool.write(struct.pack('<'+'I'*len(values),*values))
    elif index==v['groups']+1:local['output']=values
    else:local['carry'].extend(values)


def read_group(spool,size):
    raw=spool.read(4*size);need(len(raw)==4*size,'SpoolShape');return list(struct.unpack('<'+'I'*size,raw))


def value_root(p,v,spool):
    spool.seek(0,2);need(spool.tell()==4*v['count'],'SpoolShape')
    def payloads():
        for k in range(4):
            spool.seek(0)
            for size in v['sizes']:
                raw=spool.read(4*size);need(len(raw)==4*size,'SpoolShape')
                for byte in raw[k::4]:yield struct.pack('<I',byte)
            for _ in range(v['n']-v['count']):yield bytes(4)
    merkle=r.lu.merkle;return merkle.root(merkle.Tree(0,p.value_source,4*v['n'],4),payloads())


def columns(v):
    return [nmod_mat(v['la'],v['width'],[0]*(v['la']*v['width']),r.sc.P) for _ in range(v['lb'])]


def accumulate(v,partial,weights,values):
    """Producer only: each nonnegative coefficient fits by the static certificate."""
    rows=len(weights);need(len(values)==rows*v['width'],'Input')
    left=nmod_mat(v['la'],rows,[w>>(4*i)&15 for i in range(v['la']) for w in weights],r.sc.P)
    for l in range(v['lb']):partial[l]=partial[l]+left*nmod_mat(rows,v['width'],[x>>(4*l)&15 for x in values],r.sc.P)


def finish_columns(v,partial):
    output=[0]*v['width'];carry=[0]*(16*v['nc'])
    for k in range(v['k']):
        for j in range(v['width']):
            coefficient=sum(int(partial[l][k-l,j]) for l in range(v['lb']) if 0<=k-l<v['la'])
            carry[(k+1)*v['nc']+j],digit=divmod(coefficient+carry[k*v['nc']+j],16);output[j]+=digit<<(4*k)
    need(not any(carry[v['k']*v['nc']:(v['k']+1)*v['nc']]),'Boundary');return output,carry


def parent(p,v,expected,roots,states,local,spool,d):
    need(len(roots)==len(states)==v['children'] and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected+roots+states),'Root')
    sc=r.sc;t=r.scalar.Transcript(v['raw']+b''.join(expected+roots+states),d);rho=sc.challenge(t);point=[sc.challenge(t) for _ in range(v['ac'])];weights=r.scalar.eq_weights(point,d);powers=[sc.scalar(1,d)]
    for _ in range(1,v['k']):powers.append(sc.mul(powers[-1],rho))
    collapse=lambda x,size:r.zc.total((sc.mul(powers[i],sc.scalar(x>>(4*i)&15,d)) for i in range(size)),d)
    left=[collapse(x,v['la']) for x in local['probability']];right=[];spool.seek(0)
    actual_weights=nmod_mat(v['width'],d,[x for weight in weights[:v['width']] for x in weight],sc.P)
    for g,size in enumerate(v['sizes']):
        values=read_group(spool,size);plan=range_spec(p,v,g+1);_,_,n,width,_,_=r.derive(plan,d)
        # Compact roots authenticate the full uint32 only when unused bytes are zero.
        need(all(x<1<<(8*width) for x in values) and r.source_root(plan,planes(values,n,width))==roots[g+1],'Value:'+str(g)+':CommitmentMismatch')
        rows=size//v['width'];projected=[sc.scalar(0,d)]*rows
        for l in range(v['lb']):
            matrix=nmod_mat(rows,v['width'],[x>>(4*l)&15 for x in values],sc.P)*actual_weights
            for j in range(rows):projected[j]=sc.add(projected[j],sc.mul(powers[l],tuple(int(matrix[j,k]) for k in range(d))))
        right.extend(projected)
    need(spool.read(1)==b'','SpoolShape');right.extend([sc.scalar(0,d)]*(v['nr']-v['rows']))
    all_weights=nmod_mat(v['nc'],d,[x for weight in weights for x in weight],sc.P);target=sc.scalar(0,d);carry=local['carry']
    for k in range(v['k']):
        coeff=[((local['output'][j]>>(4*k)&15)+16*carry[(k+1)*v['nc']+j]-carry[k*v['nc']+j])%sc.P for j in range(v['nc'])]
        projected=nmod_mat(1,v['nc'],coeff,sc.P)*all_weights;target=sc.add(target,sc.mul(powers[k],tuple(int(projected[0,j]) for j in range(d))))
    instance=dict(id=65536*p.identity+4096,m=v['ar'],ids=[v['base']+(1<<19)+1,v['base']+(1<<19)+2],terms=[(sc.scalar(1,d),[0,1])],sum=target)
    return t,instance,[left,right]


def iterator(source):
    try:return iter(source)
    except TypeError:raise ValueError('StreamShape') from None


def prove(p,weights,groups,d):
    v=derive(p,d);groups=iterator(groups);roots=[];states=[];local={'carry':[]};expected=[None]*3;end=object();partial=columns(v)
    with tempfile.TemporaryFile() as spool:
        for index in range(v['children']):
            plan=range_spec(p,v,index)
            if index==0:values=weights
            elif index<=v['groups']:
                values=next(groups,end);need(values is not end,'StreamShape')
            elif index==v['groups']+1:
                need(next(groups,end) is end,'StreamShape');output,carries=finish_columns(v,partial);del partial;values=output
            else:
                start=(index-v['groups']-2)*v['carry_group']*v['nc'];values=carries[start:start+v['carry_group']*v['nc']]
            proof,state=r.prove(plan,values,d);roots.append(r.source_root(plan,proof['words']));states.append(state);retain(p,v,index,proof['words'],spool,local)
            if index==0:expected[0]=r.root(p.probability,planes(local['probability'],v['nr'],1 if p.schema.exponent<=7 else 2))
            elif index<=v['groups']:
                start=(index-1)*v['group_rows'];actual=unpack(plan,proof['words'])[:len(plan.caps)];accumulate(v,partial,local['probability'][start:start+len(actual)//v['width']],actual)
                del actual
                if index==v['groups']:expected[1]=value_root(p,v,spool)
            elif index==v['groups']+1:expected[2]=r.root(p.output,planes(local['output'],v['nc'],8))
            yield dict(range=index,proof=proof)
            del proof,values
        t,instance,tables=parent(p,v,expected,roots,states,local,spool,d);proof,_=r.sc.prove(t,instance,tables);yield dict(sum=proof);return t.state


def verify(p,expected,records,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root');expected=expected.copy();records=iterator(records);end=object();roots=[];states=[];local={'carry':[]};draws=Counter()
    account=dict(identities=[],lookup_reduction_numerator=0,range_reduction_numerator=0,weighted_identity_numerator=v['ac']+v['k']-1,weighted_reduction_numerator=2*v['ar'],denominator=r.sc.P**d)
    with tempfile.TemporaryFile() as spool:
        for index in range(v['children']):
            record=next(records,end);need(type(record) is dict and set(record)=={'range','proof'} and type(record['range']) is int and record['range']==index,'StreamShape');proof=record['proof'];plan=range_spec(p,v,index)
            need(type(proof) is dict and 'words' in proof,'ProofShape');root=r.source_root(plan,proof['words'])
            try:result=r.verify(plan,root,proof,d)
            except ValueError as error:raise ValueError('Range:'+str(index)+':'+str(error)) from None
            roots.append(root);states.append(result['state']);draws.update(result['draws']);a=result['account'];account['identities'].append((a['identity_numerator'],a['identity_power']))
            for key in ('lookup_reduction_numerator','range_reduction_numerator'):account[key]+=a[key]
            retain(p,v,index,proof['words'],spool,local)
            if index==0:need(r.root(p.probability,planes(local['probability'],v['nr'],1 if p.schema.exponent<=7 else 2))==expected[0],'Probability:CommitmentMismatch')
            elif index==v['groups']:need(value_root(p,v,spool)==expected[1],'Value:CommitmentMismatch')
            elif index==v['groups']+1:need(r.root(p.output,planes(local['output'],v['nc'],8))==expected[2],'Output:CommitmentMismatch')
            del record,proof,result
        tail=next(records,end);need(type(tail) is dict and set(tail)=={'sum'} and next(records,end) is end,'StreamShape');s=tail['sum']
        need(type(s) is dict and set(s)=={'rounds','final'} and type(s['rounds']) is list and len(s['rounds'])==v['ar'] and all(type(row) is list and len(row)==3 for row in s['rounds']) and type(s['final']) is list and len(s['final'])==2,'ProofShape')
        need(all(type(x) is tuple and len(x)==d and all(type(y) is int and 0<=y<r.sc.P for y in x) for row in s['rounds']+[s['final']] for x in row),'NoncanonicalField')
        t,instance,tables=parent(p,v,expected,roots,states,local,spool,d)
        try:receipt=r.sc.verify_public(t,instance,s,tables)
        except ValueError as error:raise ValueError('WeightedSum:'+str(error)) from None
        return dict(state=t.state,account=account,draws=dict(t.draws),child_draws=dict(draws),claims=receipt['claims'],sc=receipt['sc'])
