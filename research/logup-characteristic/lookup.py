"""Draft RFC-0008 A2 / RFC-0012 A8 whole lookup; full reveals, no native/ZK mode."""
from pathlib import Path
import struct
import sys
import check_sumcheck as sc
import fraction as ft
from weighted import require, Source, prepare_many
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'merkle'))
import check_merkle as merkle

UNITS, COMMIT, REPETITION, OPENINGS, UNIT, BETA, ALPHA = [ft.PREFIX+x for x in
    (b'units',b'multiplicities',b'repetition',b'openings',b'unit',b'beta',b'alpha')]


class Transcript(ft.Transcript):
    absorbs = (*ft.Transcript.absorbs,UNITS,COMMIT,REPETITION,OPENINGS)
    draws = (*ft.Transcript.draws,UNIT,BETA,ALPHA)

    def __init__(self,public,degree):
        self.events = []
        super().__init__(public,degree)

    def bind(self,label,payload):
        super().bind(label,payload)
        self.events.append((0,label))

    def absorb(self,label,payload):
        super().absorb(label,payload)
        self.events.append((0,label))

    def draw(self,label):
        value = super().draw(label)
        self.events.append((1,label))
        return value

    def challenge(self):
        value = super().challenge()
        self.events.append((1,ft.tr.CHALLENGE))
        return value


def statement(p,roots,d):
    require(type(d) is int and d in (4,8),'PlanShape')
    require(type(p) is dict and set(p) == {'id','m','b','r','sources','mus','table','sigma'},'PlanShape')
    require(type(p['id']) is int and 0 <= p['id'] < 2**60,'PlanShape')
    require(type(p['m']) is int and type(p['b']) is int and 0 <= p['b'] <= min(p['m'],30) and p['m'] <= 63,'PlanShape')
    require(type(p['r']) is int and p['r'] in (1,2),'PlanShape')
    require(type(p['sources']) is tuple and type(p['mus']) is tuple,'PlanShape')
    c = len(p['sources'])
    require(0 < c < 2**32 and len(p['mus']) == p['r'],'PlanShape')
    ids = p['sources']+p['mus']
    require(all(type(i) is int and 2 <= i < 2**64 for i in ids) and len(set(ids)) == len(ids),'PlanShape')
    table = p['table']
    require(type(table) is tuple and 1 <= len(table) <= 2**16 and all(type(row) is tuple and len(row) == c
            and all(type(x) is int and 0 <= x < sc.P for x in row) for row in table),'Table')
    require(len(set(table)) == len(table),'Table')
    require(type(p['sigma']) is tuple and len(p['sigma']) == 1 << p['m'] and
            all(type(x) is int and x in (0,1) for x in p['sigma']),'Selector')
    require(type(roots) is list and len(roots) == c and all(type(root) is bytes and len(root) == 32 for root in roots),'CommitmentShape')
    out = struct.pack('<BBQIIIBI',1,d,p['id'],p['m'],p['b'],c,p['r'],len(table))
    out += b''.join(struct.pack('<Q',i) for i in ids)+bytes(p['sigma'])
    return out+b''.join(struct.pack('<I',x) for row in table for x in row)+b''.join(roots)


def commit(identity,payloads,width):
    tree = merkle.Tree(0,identity,len(payloads),width)
    return merkle.root(tree,payloads)


def source_roots(p,xs):
    require(type(xs) is list and len(xs) == len(p['sources']) and all(type(column) is list and len(column) == 1 << p['m'] for column in xs),'OpeningShape')
    require(all(type(x) is int and 0 <= x < sc.P for column in xs for x in column),'NoncanonicalField')
    return [commit(i,[struct.pack('<I',x) for x in column],4) for i,column in zip(p['sources'],xs)]


def mu_root(p,j,values,d):
    require(type(values) is list and len(values) == len(p['table']),'OpeningShape')
    ft.fields(values,d)
    return commit(p['mus'][j],list(map(sc.encode,values)),4*d)


def begin(p,roots,d):
    t = Transcript(b'Q31/lookup-study/v1'+statement(p,roots,d),d)
    theta = []
    for j in range(p['r']):
        t.bind(UNITS,struct.pack('<QI',p['id'],j))
        theta.append([t.draw(UNIT) for _ in range(p['m']-p['b'])])
    return t,theta


def pairs(t,p,roots):
    require(len(roots) == p['r'] and all(type(root) is bytes and len(root) == 32 for root in roots),'CommitmentShape')
    payload = struct.pack('<QI',p['id'],p['r'])
    payload += b''.join(struct.pack('<Q',i)+root for i,root in zip(p['mus'],roots))
    t.bind(COMMIT,payload)  # All multiplicities precede every beta/alpha.
    result = []
    for j in range(p['r']):
        t.bind(REPETITION,struct.pack('<QI',p['id'],j))
        result.append((t.draw(BETA),t.draw(ALPHA)))
    return result


def specs(p,theta,j):
    k = (len(p['table'])-1).bit_length()
    base = 8*p['id']+4*j
    return (dict(id=4*p['id']+2*j,m=p['m'],b=p['b'],leaves=(base,base+1),theta=theta),
            dict(id=4*p['id']+2*j+1,m=k,b=k,leaves=(base+2,base+3),theta=[]))


def table_leaves(p,mu,alpha,beta,d):
    require(len(mu) == len(p['table']),'OpeningShape')
    ft.fields([*mu,alpha,beta],d)
    coefficients = ft.powers(beta,len(p['sources']),d)
    result = []
    for value,row in zip(mu,p['table']):
        z = sc.compose([(coefficient,[j]) for j,coefficient in enumerate(coefficients)],
                       [sc.scalar(x,d) for x in row],d)
        result.append((value,sc.add(alpha,sc.neg(z))))
    size = 1 << (len(result)-1).bit_length()
    return result+[(sc.scalar(0,d),sc.scalar(1,d))]*(size-len(result))


def prove_round(t,p,xs,mu,theta,pair,j):
    """Arithmetic proof producer; the whole verifier still checks root equality."""
    source,table = specs(p,theta,j)
    beta,alpha = pair
    sigma = [sc.scalar(x,t.degree) for x in p['sigma']]
    columns = [[sc.scalar(x,t.degree) for x in column] for column in xs]
    lookup,lr = ft.prove(t,source,ft.lookup_leaves(sigma,columns,alpha,beta,t.degree))
    table_proof,tr = ft.prove(t,table,table_leaves(p,mu,alpha,beta,t.degree))
    leaf,sr = ft.prove_leaf(t,source,lr,sigma,p['sources'],columns,alpha,beta)
    return dict(lookup=lookup,table=table_proof,leaf=leaf),(lr,tr,sr)


def collect(p,roots,mu_roots,part,results,pair,j,d):
    lr,tr,sr = results
    ft.root_equation(part['lookup']['root'],part['table']['root'],d)
    beta,alpha = pair
    qs = [q for _,q in table_leaves(p,[sc.scalar(0,d)]*len(p['table']),alpha,beta,d)]
    require(ft.mle(qs,tr['point'],d) == tr['values'][1],'TableDenominatorMismatch')
    claims = [dict(kind='source',id=i,root=root,point=sr['point'],value=value)
              for root,(i,value) in zip(roots,sr['claims'])]
    claims.append(dict(kind='mu',id=p['mus'][j],root=mu_roots[j],point=tr['point'],value=tr['values'][0]))
    records = [(j,'lookup',record) for record in lr['sc']]+[(j,'table',record) for record in tr['sc']]
    return claims,records+[(j,'leaf',sr['sc'])]


def consume(p,roots,proof,claims,d):
    """Full-vector revealing adapter: authenticate originals, then evaluate MLEs."""
    require(len(proof['mus']) == p['r'] and len(proof['mu_roots']) == p['r'],'OpeningShape')
    actual = source_roots(p,proof['sources'])
    require(actual == roots,'CommitmentMismatch')
    for j,values in enumerate(proof['mus']):
        require(mu_root(p,j,values,d) == proof['mu_roots'][j],'CommitmentMismatch')
    c,k = len(p['sources']),(len(p['table'])-1).bit_length()
    require(len(claims) == p['r']*(c+1),'OpeningShape')
    for index,claim in enumerate(claims):
        j,column = divmod(index,c+1)
        if column < c:
            kind,identity,root,m = 'source',p['sources'][column],roots[column],p['m']
            values = [sc.scalar(x,d) for x in proof['sources'][column]]
        else:
            kind,identity,root,m = 'mu',p['mus'][j],proof['mu_roots'][j],k
            values = proof['mus'][j]+[sc.scalar(0,d)]*((1 << k)-len(p['table']))
        require((claim['kind'],claim['id'],claim['root']) == (kind,identity,root) and len(claim['point']) == m,'OpeningIdentity')
        ft.field(claim['value'],d)
        require(ft.mle(values,claim['point'],d) == claim['value'],'OpeningMismatch')


def finish(t,p,roots,proof,theta,denominators,claims,records):
    consume(p,roots,proof,claims,t.degree)
    payload = b''.join(struct.pack('<I',x) for column in proof['sources'] for x in column)
    payload += b''.join(ft.fields(values,t.degree) for values in proof['mus'])
    t.bind(OPENINGS,payload)
    m,k = p['m'],(len(p['table'])-1).bit_length()
    f = lambda n: 3*n*(n-1)//2+2*n
    account = dict(identity_numerator=m-p['b']+(1 << m)+len(p['sources'])*len(p['table'])-1,
                   identity_power=p['r'],reduction_numerator=p['r']*(f(m)+f(k)+3*m),denominator=sc.P**t.degree)
    return dict(theta=theta,pairs=denominators,claims=claims,sc=records,account=account,state=t.state,events=t.events)


def prove(p,xs,d):
    statement(p,[bytes(32)]*len(p['sources']),d)
    roots = source_roots(p,xs)
    t,theta = begin(p,roots,d)
    records = [(selected,tuple(column[i] for column in xs)) for i,selected in enumerate(p['sigma'])]
    mus,_ = prepare_many(Source(records),p['table'],p['m'],p['b'],theta,d)
    mus = [list(values) for values in mus]
    mu_roots = [mu_root(p,j,values,d) for j,values in enumerate(mus)]
    denominators = pairs(t,p,mu_roots)
    proof = dict(mu_roots=mu_roots,rounds=[],sources=[list(column) for column in xs],mus=mus)
    claims,records = [],[]
    for j in range(p['r']):
        part,result = prove_round(t,p,xs,mus[j],theta[j],denominators[j],j)
        proof['rounds'].append(part)
        new_claims,new_records = collect(p,roots,mu_roots,part,result,denominators[j],j,d)
        claims.extend(new_claims); records.extend(new_records)
    return proof,finish(t,p,roots,proof,theta,denominators,claims,records)


def verify(p,roots,proof,d):
    t,theta = begin(p,roots,d)
    require(type(proof) is dict and set(proof) == {'mu_roots','rounds','sources','mus'},'ProofShape')
    require(type(proof['rounds']) is list and type(proof['mu_roots']) is list and
            len(proof['rounds']) == p['r'] and len(proof['mu_roots']) == p['r'] and
            type(proof['mus']) is list and len(proof['mus']) == p['r'],'ProofShape')
    denominators = pairs(t,p,proof['mu_roots'])
    claims,records = [],[]
    for j,part in enumerate(proof['rounds']):
        require(type(part) is dict and set(part) == {'lookup','table','leaf'},'ProofShape')
        source,table = specs(p,theta[j],j)
        beta,alpha = denominators[j]
        lr = ft.verify(t,source,part['lookup'])
        tr = ft.verify(t,table,part['table'])
        ft.root_equation(part['lookup']['root'],part['table']['root'],d)
        sigma = [sc.scalar(x,d) for x in p['sigma']]
        leaf = part['leaf']
        require(type(leaf) is dict and set(leaf) == {'rounds','final'} and type(leaf['rounds']) is list
                and len(leaf['rounds']) == p['m'] and all(type(row) is list and len(row) == 4 for row in leaf['rounds'])
                and type(leaf['final']) is list and len(leaf['final']) == len(p['sources'])+2,'ProofShape')
        sr = ft.verify_leaf(t,source,lr,sigma,p['sources'],part['leaf'],alpha,beta)
        new_claims,new_records = collect(p,roots,proof['mu_roots'],part,(lr,tr,sr),denominators[j],j,d)
        claims.extend(new_claims); records.extend(new_records)
    return finish(t,p,roots,proof,theta,denominators,claims,records)
