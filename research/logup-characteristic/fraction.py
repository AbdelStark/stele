"""Q31 / Draft RFC-0008 A2 fraction reduction; research, no native admission.

Dense tree state is 2N-1 pairs, before sumcheck copies. No intermediate commitment.
The returned claims require actual consumers; a receipt is not lookup acceptance.
"""
import struct
import check_sumcheck as sc
import check_transcript as tr
from weighted import require, unit

PREFIX = b'stele/v0.1/lookup/'
TREE, LAYER, GAMMA, FOLD, LEAF = [PREFIX+x for x in (b'fraction',b'layer',b'gamma',b'fold',b'leaf')]


class Transcript(tr.Transcript):
    """Candidate labels over A1 framing/sampling; production registry unchanged."""
    def __init__(self, public, degree):
        tr.registry((*tr.LABELS,TREE,LAYER,GAMMA,FOLD,LEAF))
        super().__init__(public,degree)

    def frame(self,tag,label,payload):
        require(label in (TREE,LAYER,GAMMA,FOLD,LEAF) and tag in (0,1,2),'InvalidFrame')
        return self.state+bytes([tag])+struct.pack('<I',len(label))+label+struct.pack('<Q',len(payload))+payload

    def bind(self,label,payload):
        require(label in (TREE,LAYER,LEAF),'InvalidAbsorbLabel')
        self.state = tr.blake3(self.frame(0,label,payload)).digest()

    def draw(self,label):
        require(label in (GAMMA,FOLD),'InvalidChallengeLabel')
        raw = tr.blake3(self.frame(1,label,bytes([self.degree]))).digest(length=256)
        value,consumed = tr.sample(raw,self.degree)
        payload = bytes([self.degree])+struct.pack('<I',consumed)+value
        self.state = tr.blake3(self.frame(2,label,payload)).digest()
        return struct.unpack('<'+'I'*self.degree,value)


def field(value,d):
    require(type(value) is tuple and len(value) == d and all(
        type(x) is int and 0 <= x < sc.P for x in value),'NoncanonicalField')


def fields(values,d):
    for value in values:
        field(value,d)
    return b''.join(map(sc.encode,values))


def descriptor(s,d):
    require(type(d) is int and d in (4,8),'Field')
    require(type(s) is dict and set(s) == {'id','m','b','leaves','theta'},'TreeShape')
    require(type(s['id']) is int and 0 <= s['id'] < 2**64,'TreeShape')
    require(type(s['m']) is int and type(s['b']) is int and 0 <= s['b'] <= s['m'] <= 63,'TreeShape')
    ids = s['leaves']
    require(type(ids) is tuple and len(ids) == 2 and all(type(i) is int and 0 <= i < 2**64 for i in ids)
            and ids[0] != ids[1],'TreeShape')
    require(type(s['theta']) is list and len(s['theta']) == s['m']-s['b'],'TreeShape')
    return struct.pack('<BBQIIQQ',1,d,s['id'],s['m'],s['b'],*ids)+fields(s['theta'],d)


def proof_bytes(s,proof,d):
    descriptor(s,d)
    require(type(proof) is dict and set(proof) == {'root','steps'},'TreeShape')
    require(type(proof['root']) in (tuple,list) and len(proof['root']) == 2,'TreeShape')
    require(type(proof['steps']) is list and len(proof['steps']) == s['m'],'TreeShape')
    encoded = fields(proof['root'],d)
    for k,step in enumerate(proof['steps']):
        require(type(step) is dict and set(step) == {'rounds','final'},'TreeShape')
        require(type(step['rounds']) is list and len(step['rounds']) == k and
                type(step['final']) is list and len(step['final']) == 5,'TreeShape')
        for row in step['rounds']:
            require(type(row) is list and len(row) == 4,'TreeShape')
            encoded += fields(row,d)
        encoded += fields(step['final'],d)
    return encoded


def mle(values,point,d):
    require(len(values) == 1 << len(point),'SourceShape')
    fields(point,d)
    fields(values,d)
    result = sc.scalar(0,d)
    for i,value in enumerate(values):
        result = sc.add(result,sc.mul(unit(i,point,d),value))
    return result


def equality(r,u,d):
    require(len(r) == len(u),'Point')
    result,one = sc.scalar(1,d),sc.scalar(1,d)
    for x,y in zip(r,u):
        result = sc.mul(result,sc.add(sc.mul(x,y),sc.mul(sc.add(one,sc.neg(x)),sc.add(one,sc.neg(y)))))
    return result


def weights(s,k,d):
    one = sc.scalar(1,d)
    return (sc.add(one,sc.neg(s['theta'][k])),s['theta'][k]) if k < len(s['theta']) else (one,one)


def layer(t,s,k,r,values):
    t.bind(LAYER,struct.pack('<QI',s['id'],k)+fields([*r,*values],t.degree))
    gamma = t.draw(GAMMA)
    a,b = weights(s,k,t.degree)
    return dict(id=k,m=k,ids=[0,1,2,3,4],terms=[(a,[0,3,4]),(b,[2,1,4]),(gamma,[1,3,4])],
                sum=sc.add(values[0],sc.mul(gamma,values[1])))


def advance(t,r,u,final):
    require(final[4] == equality(r,u,t.degree),'CoefficientMismatch')
    tau = t.draw(FOLD)  # A1 Final already contains all four children and eq.
    p0,q0,p1,q1,_ = final
    blend = lambda a,b: sc.add(a,sc.mul(tau,sc.add(b,sc.neg(a))))
    return [*u,tau],(blend(p0,p1),blend(q0,q1))


def receipt(s,r,values,records):
    m = s['m']
    return dict(point=r,values=tuple(values),ids=s['leaves'],sc=records,numerator=3*m*(m-1)//2+2*m)


def prove(t,s,leaves):
    desc = descriptor(s,t.degree)
    require(len(leaves) == 1 << s['m'] and all(len(row) == 2 for row in leaves),'SourceShape')
    fields([v for row in leaves for v in row],t.degree)
    levels = [None]*s['m']+[leaves]
    for k in reversed(range(s['m'])):
        a,b = weights(s,k,t.degree)
        children = levels[k+1]
        levels[k] = []
        for i in range(0,len(children),2):
            p0,q0 = children[i]; p1,q1 = children[i+1]
            levels[k].append((sc.add(sc.mul(a,sc.mul(p0,q1)),sc.mul(b,sc.mul(p1,q0))),sc.mul(q0,q1)))
    proof = dict(root=tuple(levels[0][0]),steps=[])
    t.bind(TREE,desc+fields(proof['root'],t.degree))
    r,values,records = [],proof['root'],[]
    for k in range(s['m']):
        instance = layer(t,s,k,r,values)
        children = levels[k+1]
        tables = [[children[2*i+side][j] for i in range(1 << k)] for side,j in ((0,0),(0,1),(1,0),(1,1))]
        tables.append([unit(i,r,t.degree) for i in range(1 << k)])
        step,u = sc.prove(t,instance,tables)
        proof['steps'].append(step)
        records.append(dict(id=k,m=k,degree=3,field_degree=t.degree,numerator=3*k))
        r,values = advance(t,r,u,step['final'])
    return proof,receipt(s,r,values,records)


def verify(t,s,proof):
    proof_bytes(s,proof,t.degree)  # Check all counts/canonical fields before absorption.
    t.bind(TREE,descriptor(s,t.degree)+fields(proof['root'],t.degree))
    r,values,records = [],proof['root'],[]
    for k,step in enumerate(proof['steps']):
        result = sc.verify_reduction(t,layer(t,s,k,r,values),step)
        records.append(result['sc'])
        r,values = advance(t,r,result['point'],step['final'])
    return receipt(s,r,values,records)


def consume(result,leaves,d):
    """Public original-array consumer; never use the prover's internal tree."""
    require(all(len(row) == 2 for row in leaves),'SourceShape')
    actual = tuple(mle([row[j] for row in leaves],result['point'],d) for j in range(2))
    require(actual == result['values'],'LeafMismatch')


def root_equation(left,right,d):
    fields([*left,*right],d)
    p,q = left; a,b = right
    require(q != sc.scalar(0,d) and b != sc.scalar(0,d),'Pole')
    require(sc.mul(p,b) == sc.mul(a,q),'RootMismatch')


def selector(sigma,m,d):
    require(len(sigma) == 1 << m,'SourceShape')
    fields(sigma,d)
    require(all(v in (sc.scalar(0,d),sc.scalar(1,d)) for v in sigma),'Selector')


def powers(beta,count,d):
    result,value = [],sc.scalar(1,d)
    for _ in range(count):
        result.append(value)
        value = sc.mul(value,beta)
    return result


def lookup_leaves(sigma,xs,alpha,beta,d):
    require(len(sigma) > 0 and len(sigma) & (len(sigma)-1) == 0 and len(xs) > 0,'SourceShape')
    selector(sigma,len(sigma).bit_length()-1,d)
    fields([alpha,beta],d)
    for source in xs:
        require(len(source) == len(sigma),'SourceShape')
        fields(source,d)
    coefficients = powers(beta,len(xs),d)
    leaves = []
    for i,selected in enumerate(sigma):
        z = sc.compose([(c,[j]) for j,c in enumerate(coefficients)],[source[i] for source in xs],d)
        q = sc.add(sc.scalar(1,d),sc.mul(selected,sc.add(sc.add(alpha,sc.scalar(-1,d)),sc.neg(z))))
        leaves.append((selected,q))
    return leaves


def leaf_instance(t,s,result,sigma,ids,alpha,beta):
    d = t.degree
    desc = descriptor(s,d)
    selector(sigma,s['m'],d)
    require(result['ids'] == s['leaves'] and len(result['point']) == s['m'] and len(result['values']) == 2,'SourceShape')
    require(0 < len(ids) < 2**32 and all(type(i) is int and 2 <= i < 2**64 for i in ids)
            and len(set(ids)) == len(ids),'SourceShape')
    data = fields([alpha,beta,*result['point'],*result['values']],d)
    p,q = result['values']
    require(p == mle(sigma,result['point'],d),'SelectorMismatch')
    t.bind(LEAF,desc+struct.pack('<I',len(ids))+b''.join(struct.pack('<Q',i) for i in ids)+data)
    total = sc.add(sc.add(sc.scalar(1,d),sc.mul(sc.add(alpha,sc.scalar(-1,d)),p)),sc.neg(q))
    return dict(id=s['id'],m=s['m'],ids=[0,1,*ids],sum=total,
                terms=[(c,[0,1,j+2]) for j,c in enumerate(powers(beta,len(ids),d))])


def leaf_result(t,original,sigma,point,final,record,ids):
    require(final[0] == equality(original['point'],point,t.degree),'CoefficientMismatch')
    require(final[1] == mle(sigma,point,t.degree),'SelectorMismatch')
    return dict(point=point,claims=list(zip(ids,final[2:])),sc=record)


def prove_leaf(t,s,result,sigma,ids,xs,alpha,beta):
    require(len(xs) == len(ids) and all(len(source) == len(sigma) for source in xs),'SourceShape')
    for source in xs:
        fields(source,t.degree)
    instance = leaf_instance(t,s,result,sigma,ids,alpha,beta)
    tables = [[unit(i,result['point'],t.degree) for i in range(len(sigma))],sigma,*xs]
    proof,point = sc.prove(t,instance,tables)
    record = dict(id=s['id'],m=s['m'],degree=3,field_degree=t.degree,numerator=3*s['m'])
    return proof,leaf_result(t,result,sigma,point,proof['final'],record,ids)


def verify_leaf(t,s,result,sigma,ids,proof,alpha,beta):
    instance = leaf_instance(t,s,result,sigma,ids,alpha,beta)
    for row in [*proof['rounds'],proof['final']]:
        fields(row,t.degree)
    reduced = sc.verify_reduction(t,instance,proof)
    return leaf_result(t,result,sigma,reduced['point'],proof['final'],reduced['sc'],ids)


def consume_sources(result,ids,xs,d):
    require(len(xs) == len(ids) and [i for i,_ in result['claims']] == list(ids),'SourceShape')
    for source,(_,value) in zip(xs,result['claims']):
        require(mle(source,result['point'],d) == value,'SourceMismatch')
