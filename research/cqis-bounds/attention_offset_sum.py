"""Draft RFC-0004 A3/A6 / RFC-0009 A2: actual weighted offset columns.

Linear source projections and complete ranges; revealing originals remain.
Signed sums, canonical value preparation and native/private ownership are separate.
"""
from dataclasses import dataclass
import struct
import attention_sum_bounds as bounds
import wide_range as r

need=r.need
PREFIX=b'stele/research/q26/attention-offset-sum/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: bounds.Spec
    positions: tuple
    allowed: tuple
    block: int
    identity: int
    probability: int
    value_source: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec');constants=bounds.constants(p.schema)
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    need(type(p.positions) is tuple and 1<=len(p.positions)<=constants['term_cap'] and all(type(x) is int and 0<=x<p.schema.length for x in p.positions) and all(x<y for x,y in zip(p.positions,p.positions[1:])),'Spec')
    rows=len(p.positions);width=p.schema.width;count=rows*width;need(count<=16384,'Capacity')
    need(type(p.allowed) is tuple and len(p.allowed)==rows and all(type(x) is bool for x in p.allowed),'Spec')
    need(type(p.block) is int and 0<=p.block<=constants['block_max'] and (p.schema.accumulation=='exact' or all(x//1024==p.block for x in p.positions)),'Spec')
    base=(1<<63)+(1<<18)*p.identity;external=(p.probability,p.value_source,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in external) and len(set(external))==3,'Spec')
    column=bounds.column_specs(p.schema)['entry_columns']['offset_sum'];cert=bounds.limbs.derive(column);k=len(cert['result_caps']);need(k+1<=16 and 2*max(cert['lhs']+cert['rhs'])<r.sc.P,'FieldBound')
    a=(count-1).bit_length();ar=(rows-1).bit_length();ac=(width-1).bit_length();n,nr,nc=1<<a,1<<ar,1<<ac
    size=max(1,(max(cert['carry_caps']).bit_length()+7)//8);wc=1<<(size-1).bit_length();group=min(16,65536//nc,131072//(nc*wc))
    ranges=dict(probability=r.Spec(4096*p.identity+1,base+11,tuple(constants['probability_max']*int(bit) for bit in p.allowed),p.repetitions),value=r.Spec(4096*p.identity+2,base+1,(2*constants['restored_max'],)*count,p.repetitions),output=r.Spec(4096*p.identity+3,base+2,(constants['offset_sum_max'],)*width,p.repetitions))
    for g in range(16//group):
        caps=tuple(cert['carry_caps'][j] if j<=k and channel<width else 0 for j in range(g*group,(g+1)*group) for channel in range(nc))
        ranges['carry_'+str(g)]=r.Spec(4096*p.identity+4+g,base+3+g,caps,p.repetitions)
    for child in ranges.values():r.derive(child,d)
    encoded=bounds.encode(p.schema);raw=PREFIX+struct.pack('<BBBQQQQIII',1,d,p.repetitions,p.identity,*external,p.block,rows,len(encoded))+encoded
    raw+=b''.join(struct.pack('<I',x) for x in p.positions)+bytes(p.allowed)
    return dict(constants=constants,column=column,cert=cert,k=k,a=a,ar=ar,ac=ac,n=n,nr=nr,nc=nc,rows=rows,width=width,count=count,group=group,ranges=ranges,names=tuple(ranges),aux=tuple(ranges),base=base,raw=raw)


def witness(p,weights,values):
    v=derive(p,4);Q,S=v['constants']['probability_max'],v['constants']['restored_max']
    need(type(weights) is list and len(weights)==v['rows'] and all(type(x) is int and 0<=x<=Q*int(bit) for x,bit in zip(weights,p.allowed)),'Input')
    need(type(values) is list and len(values)==v['count'] and all(type(x) is int and 0<=x<=2*S for x in values),'Input')
    width,nc=v['width'],v['nc'];output=[sum(w*values[j*width+c] for j,w in enumerate(weights)) for c in range(width)];carry=[[0]*nc for _ in range(16)]
    la,lb=len(v['cert']['left_caps']),len(v['cert']['right_caps'])
    for k in range(v['k']):
        for channel in range(width):
            coefficient=sum((w>>(4*i)&15)*(values[j*width+channel]>>(4*(k-i))&15) for j,w in enumerate(weights) for i in range(la) if 0<=k-i<lb)
            carry[k+1][channel]=(coefficient+carry[k][channel])//16
    need(not any(carry[v['k']]),'Boundary');result=dict(probability=weights.copy(),value=values.copy(),output=output)
    for g in range(16//v['group']):result['carry_'+str(g)]=sum(carry[g*v['group']:(g+1)*v['group']],[])
    return result


def unpack(child,words,d):
    _,_,n,width,_,_=r.derive(child,d);r.vector(words,n*width);return [sum(words[j*n+i]<<(8*j) for j in range(width)) for i in range(n)]


def full(v,name,words,width):
    _,_,n,compact,_,_=r.derive(v['ranges'][name],4);r.vector(words,n*compact);need(compact<=width,'Capacity');return words+[0]*(n*(width-compact))


def roots(p,proof):
    v=derive(p,4);return [r.root(p.probability,full(v,'probability',proof['probability']['words'],1 if p.schema.exponent<=7 else 2)),r.root(p.value_source,full(v,'value',proof['value']['words'],4)),r.root(p.output,full(v,'output',proof['output']['words'],8))]


def expected_roots(p,weights,values):
    v=derive(p,4);w=witness(p,weights,values);pw=r.witness(v['ranges']['probability'],weights)[0]
    def planes(xs,size,width):return [x>>(8*j)&255 for j in range(width) for x in xs+[0]*(size-len(xs))]
    return [r.root(p.probability,full(v,'probability',pw,1 if p.schema.exponent<=7 else 2)),r.root(p.value_source,planes(values,v['n'],4)),r.root(p.output,planes(w['output'],v['nc'],8))]


def part(p,proof,rho,point,d):
    v=derive(p,d);sc=r.sc;zero=sc.scalar(0,d);powers=[sc.scalar(1,d)]
    for _ in range(1,v['k']):powers.append(sc.mul(powers[-1],rho))
    channel_weights=r.scalar.eq_weights(point,d);data={name:unpack(child,proof[name]['words'],d) for name,child in v['ranges'].items()};carry=sum((data[name] for name in v['names'] if name.startswith('carry_')),[])
    def collapse(value,size):return r.zc.total((sc.mul(powers[i],sc.scalar(value>>(4*i)&15,d)) for i in range(size)),d)
    left=[collapse(x,len(v['cert']['left_caps'])) for x in data['probability']];right=[zero]*v['nr'];target=zero
    for j in range(v['rows']):right[j]=r.zc.total((sc.mul(channel_weights[channel],collapse(data['value'][j*v['width']+channel],len(v['cert']['right_caps']))) for channel in range(v['width'])),d)
    for channel,weight in enumerate(channel_weights):
        # Whole ranges precede the faithful radix-16 column identity; no wide
        # scalar product is reduced modulo p to stand in for this identity.
        local=r.zc.total((sc.mul(powers[k],sc.scalar((data['output'][channel]>>(4*k)&15)+16*carry[(k+1)*v['nc']+channel]-carry[k*v['nc']+channel],d)) for k in range(v['k'])),d)
        target=sc.add(target,sc.mul(weight,local))
    return dict(id=16384*p.identity+512,m=v['ar'],ids=[v['base']+16,v['base']+17],terms=[(sc.scalar(1,d),[0,1])],sum=target),[left,right]


def transcript(v,external,aux,states,d):
    need(type(external) is list and len(external)==3 and type(aux) is list and len(aux)==len(v['aux']) and type(states) is list and len(states)==len(v['names']) and all(type(x) is bytes and len(x)==32 for x in external+aux+states),'Root')
    t=r.scalar.Transcript(v['raw']+b''.join(external+aux+states),d);rho=r.sc.challenge(t);point=[r.sc.challenge(t) for _ in range(v['ac'])];return t,rho,point


def prepare(p,weights,values,d):
    v=derive(p,d);w=witness(p,weights,values);return {name:r.prove(child,w[name],d) for name,child in v['ranges'].items()}


def assemble(p,pairs,d):
    """Producer only; complete verification supplies all authoritative states."""
    v=derive(p,d);proof={name:pairs[name][0] for name in v['names']};proof['roots']={name:r.source_root(v['ranges'][name],proof[name]['words']) for name in v['aux']}
    t,rho,point=transcript(v,roots(p,proof),[proof['roots'][name] for name in v['aux']],[pairs[name][1] for name in v['names']],d);proof['sum']=r.sc.prove(t,*part(p,proof,rho,point,d))[0]
    return proof,t.state


def prove(p,weights,values,d):
    return assemble(p,prepare(p,weights,values,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)==set(v['names'])|{'roots','sum'} and type(proof['roots']) is dict and set(proof['roots'])==set(v['aux']),'ProofShape');need(all(type(x) is bytes and len(x)==32 for x in proof['roots'].values()),'Root');children=[]
    for name,child in v['ranges'].items():
        try:
            children.append(r.verify(child,proof['roots'][name],proof[name],d))
            if name=='probability':need(r.root(p.probability,full(v,name,proof[name]['words'],1 if p.schema.exponent<=7 else 2))==expected[0],'CommitmentMismatch')
            if name=='value':need(r.root(p.value_source,full(v,name,proof[name]['words'],4))==expected[1],'CommitmentMismatch')
            if name=='output':need(r.root(p.output,full(v,name,proof[name]['words'],8))==expected[2],'CommitmentMismatch')
        except ValueError as error:raise ValueError(name.title()+':'+str(error)) from None
    s=proof['sum'];need(type(s) is dict and set(s)=={'rounds','final'} and type(s['rounds']) is list and len(s['rounds'])==v['ar'] and all(type(row) is list and len(row)==3 for row in s['rounds']) and type(s['final']) is list and len(s['final'])==2,'ProofShape')
    need(all(type(x) is tuple and len(x)==d and all(type(y) is int and 0<=y<r.sc.P for y in x) for row in s['rounds']+[s['final']] for x in row),'NoncanonicalField')
    t,rho,point=transcript(v,expected,[proof['roots'][name] for name in v['aux']],[child['state'] for child in children],d);instance,tables=part(p,proof,rho,point,d)
    try:receipt=r.sc.verify_public(t,instance,s,tables)
    except ValueError as error:raise ValueError('WeightedSum:'+str(error)) from None
    accounts=[child['account'] for child in children]
    return dict(state=t.state,children=children,sc=[receipt['sc']],claims=receipt['claims'],draws=dict(t.draws),account=dict(identities=[(x['identity_numerator'],x['identity_power']) for x in accounts],lookup_reduction_numerator=sum(x['lookup_reduction_numerator'] for x in accounts),range_reduction_numerator=sum(x['range_reduction_numerator'] for x in accounts),weighted_identity_numerator=v['k']-1+v['ac'],weighted_reduction_numerator=receipt['sc']['numerator'],denominator=r.sc.P**d))
