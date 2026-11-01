# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q31 complete committed lookup checks; revealing research adapter, not ZK/PCS."""
import copy
from collections import Counter
from pathlib import Path
import random
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as sc
import lookup as lu
from check_fraction import evaluate, rejects


def fixture(m=2,count=3,width=2,repetitions=2):
    table = tuple(tuple(3*j+i for j in range(width)) for i in range(count))
    p = dict(id=17,m=m,b=min(m,1),r=repetitions,sources=tuple(range(100,100+width)),
             mus=tuple(range(200,200+repetitions)),table=table,sigma=tuple(1 for _ in range(1 << m)))
    xs = [[table[i % count][j] for i in range(1 << m)] for j in range(width)]
    return p,xs


def check_honest():
    rng = random.Random(310807)
    total = 0
    for d in (4,8):
        for repetitions in (1,2):
            for case in range(24):
                p,xs = fixture(case % 4,1+case % 5,1+case % 2,repetitions)
                p['b'] = case % (p['m']+1)
                p['sigma'] = tuple(rng.randrange(2) for _ in p['sigma'])
                for i,selected in enumerate(p['sigma']):
                    if not selected:
                        for j,column in enumerate(xs):
                            column[i] = 1000+j  # Inactive invalid values are excluded.
                roots = lu.source_roots(p,xs)
                proof,pr = lu.prove(p,xs,d)
                vr = lu.verify(p,roots,proof,d)
                assert pr == vr and len(vr['claims']) == repetitions*(len(xs)+1)
                for j,point in enumerate(vr['theta']):
                    expected = []
                    for row in p['table']:
                        counts = [0]*(1 << (p['m']-p['b']))
                        for i,selected in enumerate(p['sigma']):
                            if selected and tuple(column[i] for column in xs) == row:
                                counts[i >> p['b']] += 1
                        expected.append(evaluate([sc.scalar(n,d) for n in counts],point))
                    assert proof['mus'][j] == expected
                k = (len(p['table'])-1).bit_length()
                tree_loss = lambda m: 3*m*(m-1)//2+2*m
                assert vr['account'] == dict(identity_numerator=p['m']-p['b']+(1 << p['m'])+len(xs)*len(p['table'])-1,
                    identity_power=repetitions,reduction_numerator=repetitions*(tree_loss(p['m'])+tree_loss(k)+3*p['m']),
                    denominator=sc.P**d)
                assert sum(record['numerator'] for _,_,record in vr['sc'])+repetitions*2*(p['m']+k) == vr['account']['reduction_numerator']
                events = vr['events']
                counts = Counter(label for tag,label in events if tag == 1)
                m = p['m']
                assert counts == Counter({lu.UNIT:repetitions*(m-p['b']),lu.BETA:repetitions,lu.ALPHA:repetitions,
                    lu.ft.GAMMA:repetitions*(m+k),lu.ft.FOLD:repetitions*(m+k),
                    lu.ft.tr.CHALLENGE:repetitions*(m*(m-1)//2+k*(k-1)//2+m)})
                commitment = events.index((0,lu.COMMIT))
                assert events.count((0,lu.COMMIT)) == 1
                first_tree = events.index((0,lu.ft.TREE))
                for at,(tag,label) in enumerate(events):
                    if tag == 1 and label == lu.UNIT:
                        assert at < commitment
                    if tag == 1 and label in (lu.BETA,lu.ALPHA):
                        assert commitment < at < first_tree
                    if tag == 1 and label == lu.ft.FOLD:
                        assert events[at-1] == (0,sc.FINAL)
                    if tag == 1 and label == lu.ft.GAMMA:
                        assert events[at-1] == (0,lu.ft.LAYER)
                assert events[-1] == (0,lu.OPENINGS)
                for claim in vr['claims']:
                    assert len(claim['point']) == (k if claim['kind'] == 'mu' else p['m'])
                if repetitions == 2:
                    assert proof['mu_roots'][0] != proof['mu_roots'][1]
                    assert vr['pairs'][0] != vr['pairs'][1]
                    if p['m'] > p['b']:
                        assert vr['theta'][0] != vr['theta'][1]
                total += 1
    assert total == 96
    return total


def check_bindings():
    d = 4
    p,xs = fixture()
    roots = lu.source_roots(p,xs)
    proof,receipt = lu.prove(p,xs,d)
    wrong = copy.deepcopy(proof)
    wrong['mus'][0][0] = sc.add(wrong['mus'][0][0],sc.scalar(1,d))
    rejects('CommitmentMismatch',lambda: lu.verify(p,roots,wrong,d))
    wrong = copy.deepcopy(proof); wrong['sources'][0][0] += 1
    rejects('CommitmentMismatch',lambda: lu.verify(p,roots,wrong,d))
    wrong = copy.deepcopy(proof); wrong['rounds'].pop()
    rejects('ProofShape',lambda: lu.verify(p,roots,wrong,d))
    wrong = copy.deepcopy(proof); wrong['mu_roots'].pop()
    rejects('ProofShape',lambda: lu.verify(p,roots,wrong,d))
    wrong = copy.deepcopy(proof); wrong['mus'][0].append(sc.scalar(0,d))
    rejects('OpeningShape',lambda: lu.verify(p,roots,wrong,d))
    wrong = copy.deepcopy(proof); wrong['mus'][0][0] = (sc.P,0,0,0)
    rejects('NoncanonicalField',lambda: lu.verify(p,roots,wrong,d))
    wrong = copy.deepcopy(proof); wrong['sources'][0][0] = True
    rejects('NoncanonicalField',lambda: lu.verify(p,roots,wrong,d))
    # A truthful opening cannot discharge a changed evaluation or source identity.
    claims = copy.deepcopy(receipt['claims']); claims[0]['value'] = sc.add(claims[0]['value'],sc.scalar(1,d))
    rejects('OpeningMismatch',lambda: lu.consume(p,roots,proof,claims,d))
    claims = copy.deepcopy(receipt['claims']); claims[0]['id'] = p['sources'][1]
    rejects('OpeningIdentity',lambda: lu.consume(p,roots,proof,claims,d))
    rejects('OpeningShape',lambda: lu.consume(p,roots,proof,receipt['claims'][:-1],d))
    wrong = copy.deepcopy(proof); wrong['mu_roots'][1] = wrong['mu_roots'][0]
    rejects('CommitmentMismatch',lambda: lu.consume(p,roots,wrong,receipt['claims'],d))
    bad = {**p,'b':31}
    rejects('PlanShape',lambda: lu.statement(bad,roots,d))
    bad = {**p,'r':1}
    rejects('PlanShape',lambda: lu.statement(bad,roots,d))
    bad = {**p,'table':(p['table'][0],p['table'][0])}
    rejects('Table',lambda: lu.statement(bad,roots,d))
    bad = {**p,'sigma':(2,)+p['sigma'][1:]}
    rejects('Selector',lambda: lu.statement(bad,roots,d))
    # Replaying a repetition or changing its public selector is not a new proof.
    p,xs = fixture(0,1,1,2)
    roots = lu.source_roots(p,xs)
    proof,_ = lu.prove(p,xs,d)
    wrong = copy.deepcopy(proof); wrong['rounds'][1] = wrong['rounds'][0]
    rejects('FinalEvaluationMismatch',lambda: lu.verify(p,roots,wrong,d))
    p,xs = fixture(0,1,1,1)
    p['sigma'] = (0,); xs[0][0] = 99
    roots = lu.source_roots(p,xs)
    proof,_ = lu.prove(p,xs,d)
    rejects('SelectorMismatch',lambda: lu.verify({**p,'sigma':(1,)},roots,proof,d))


def check_false_identity():
    d = 4
    p,xs = fixture(1,3,1,1)
    xs[0][0] = 99  # Fixed selected source outside the table, before unit draws.
    roots = lu.source_roots(p,xs)
    t,theta = lu.begin(p,roots,d)
    mus = [[sc.scalar(0,d)]*len(p['table'])]
    mu_roots = [lu.mu_root(p,j,values,d) for j,values in enumerate(mus)]
    pairs = lu.pairs(t,p,mu_roots)
    round_proof,_ = lu.prove_round(t,p,xs,mus[0],theta[0],pairs[0],0)
    proof = dict(mu_roots=mu_roots,rounds=[round_proof],sources=xs,mus=mus)
    rejects('RootMismatch',lambda: lu.verify(p,roots,proof,d))
    # Both bound denominators are mandatory even when every numerator is zero.
    zero,one = sc.scalar(0,d),sc.scalar(1,d)
    p,xs = fixture(0,1,1,1)
    p['sigma'] = (0,)
    leaves = lu.table_leaves(p,[zero],zero,one,d)
    assert leaves == [(zero,zero)]  # alpha equals the real table value.
    rejects('Pole',lambda: lu.ft.root_equation((zero,one),leaves[0],d))


def check_table_padding():
    d = 4
    p,xs = fixture(0,3,1,1)
    roots = lu.source_roots(p,xs)
    t,theta = lu.begin(p,roots,d)
    mu = [sc.scalar(x,d) for x in (1,0,0)]
    mu_roots = [lu.mu_root(p,0,mu,d)]
    beta,alpha = lu.pairs(t,p,mu_roots)[0]
    source,table = lu.specs(p,theta[0],0)
    columns = [[sc.scalar(x,d) for x in xs[0]]]
    sigma = [sc.scalar(1,d)]
    left,lr = lu.ft.prove(t,source,lu.ft.lookup_leaves(sigma,columns,alpha,beta,d))
    table_values = lu.table_leaves(p,mu,alpha,beta,d)
    table_values[-1] = (sc.scalar(0,d),sc.scalar(2,d))
    right,_ = lu.ft.prove(t,table,table_values)
    leaf,_ = lu.ft.prove_leaf(t,source,lr,sigma,p['sources'],columns,alpha,beta)
    # The wrong padding leaves the rational value unchanged; root equality passes.
    lu.ft.root_equation(left['root'],right['root'],d)
    proof = dict(mu_roots=mu_roots,rounds=[dict(lookup=left,table=right,leaf=leaf)],sources=xs,mus=[mu])
    rejects('TableDenominatorMismatch',lambda: lu.verify(p,roots,proof,d))


def check_early_denominator():
    d = 4
    p,xs = fixture(0,1,1,1)
    xs[0][0] = 99
    roots = lu.source_roots(p,xs)
    early,_ = lu.begin(p,roots,d)
    _,alpha = lu.pairs(early,p,[bytes(32)])[0]
    divisor = sc.add(alpha,sc.scalar(-99,d))
    inverse,base,exponent = sc.scalar(1,d),divisor,sc.P**d-2
    while exponent:
        if exponent & 1:
            inverse = sc.mul(inverse,base)
        base,exponent = sc.mul(base,base),exponent >> 1
    mu = [sc.mul(alpha,inverse)]  # Fits the bad identity at the early alpha.
    assert sc.mul(mu[0],divisor) == alpha
    t,theta = lu.begin(p,roots,d)
    mu_roots = [lu.mu_root(p,0,mu,d)]
    pair = lu.pairs(t,p,mu_roots)[0]
    assert pair[1] != alpha
    part,_ = lu.prove_round(t,p,xs,mu,theta[0],pair,0)
    proof = dict(mu_roots=mu_roots,rounds=[part],sources=xs,mus=[mu])
    rejects('RootMismatch',lambda: lu.verify(p,roots,proof,d))


def check_limb_view():
    """Draft A5 algebra only: independent MLE versus actual matrix functionals."""
    cases = 0
    for d in (4,8):
        zero,one = sc.scalar(0,d),sc.scalar(1,d)
        basis = [tuple(int(a == j) for a in range(d)) for j in range(d)]
        assert [sc.encode(e) for e in basis] == [
            b''.join(int(a == j).to_bytes(4,'little') for a in range(d))
            for j in range(d)]

        def eq_weights(point):
            weights = [one]
            for x in point:
                weights = [v for w in weights for v in
                           (sc.mul(w,sc.add(one,sc.neg(x))),sc.mul(w,x))]
            return weights

        def pieces(limbs,point,ell,t):
            rows,suffix = 1 << ell,1 << (len(point)-ell)
            q,s = divmod(t,suffix)
            left,right = eq_weights(point[:ell]),eq_weights(point[ell:])
            result = []
            for piece,present in ((0,q > 0),(1,s > 0)):
                if not present:
                    continue
                a = [w if (u < q if piece == 0 else u == q) else zero
                     for u,w in enumerate(left)]
                b = [sc.mul(w,basis[j]) if piece == 0 or v < s else zero
                     for v,w in enumerate(right) for j in range(d)]
                value = zero
                for column,weight in enumerate(b):
                    # First form the physical row combination, then dot with b.
                    row_value = zero
                    for u in range(rows):
                        row_value = sc.add(row_value,sc.mul(a[u],
                            sc.scalar(limbs[u*suffix*d+column],d)))
                    value = sc.add(value,sc.mul(row_value,weight))
                result.append((piece,value))
            assert len(result) == int(q > 0)+int(s > 0)
            return result

        for k in range(5):
            n = 1 << k
            # Every physical tail is deliberately nonzero, including nonbase limbs.
            records = [tuple(11+37*i+5*j for j in range(d)) for i in range(n)]
            limbs = [a for row in records for a in row]
            for t in range(1,n+1):
                point = [tuple(19+7*i+3*j for j in range(d)) for i in range(k)]
                if t % 3 == 0:
                    point = [sc.scalar(i % 2,d) for i in range(k)]
                # This independent oracle folds logical K records, not coefficients.
                expected = evaluate(records[:t]+[zero]*(n-t),point)
                for ell in range(k+1):
                    actual = pieces(limbs,point,ell,t)
                    assert sc.add(actual[0][1],actual[1][1] if len(actual) == 2 else zero) == expected
                    changed = limbs[:]
                    if t < n:
                        changed[t*d] += 1
                        assert pieces(changed,point,ell,t) == actual
                    cases += 1
        # Concrete wrong-basis and unmasked-tail results differ from the true view.
        scalar = tuple(range(1,d+1))
        assert pieces(list(reversed(scalar)),[],0,1)[0][1] != evaluate([scalar],[])
        point = [tuple(13+3*j for j in range(d))]
        assert pieces(list(scalar+scalar),point,0,2)[0][1] != evaluate([scalar,zero],point)
    assert cases == 258
    return cases


if __name__ == '__main__' and sys.argv[1:] == ['--limb-view-only']:
    print(f'{check_limb_view()} QM31/OM31 limb-view cases: rank-two functionals match independent MLEs; no native PCS/NC credit')
elif __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('usage: check_lookup.py [--limb-view-only]')
    view_cases = check_limb_view()
    total = check_honest()
    check_bindings()
    check_false_identity()
    check_table_padding()
    check_early_denominator()
    print(f'{total} complete QM31/OM31 single/paired lookups: committed source/multiplicity consumers and accounting agree')
    print('tampered commitments, openings, identities, shapes, invalid selected value and pole controls reject; no ZK/native NC credit')
    print(f'{view_cases} canonical limb-view identities and physical-tail projections agree; no native PCS/NC credit')
