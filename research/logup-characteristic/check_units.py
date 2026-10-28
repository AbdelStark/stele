# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q31 weighted-unit evidence; no native lookup, simulator or NC credit."""
from itertools import product
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
from check_sumcheck import P, scalar, add, neg, mul, fold
import weighted


def finite_unit(group, point, p):
    value = 1
    for k,t in enumerate(point):
        value = value*(t if group >> (len(point)-k-1) & 1 else 1-t) % p
    return value


def check_subsets():
    cases = roots_checked = 0
    for p,b,h in ((3,1,0),(3,1,1),(3,1,2),(5,2,1)):
        size = 1 << (b+h)
        for subset in range(1,1 << size):
            counts = [sum((subset >> i) & 1 for i in range(g << b,(g+1) << b))
                      for g in range(1 << h)]
            assert max(counts) < p and any(counts)
            zeros = 0
            for theta in product(range(p), repeat=h):
                value = sum(n*finite_unit(g,theta,p) for g,n in enumerate(counts)) % p
                if all(t in (0,1) for t in theta):
                    group = sum(t << (h-k-1) for k,t in enumerate(theta))
                    assert value == counts[group]
                zeros += value == 0
                roots_checked += 1
            assert zeros*p <= h*p**h
            cases += 1
    assert cases == 528
    # Illegal repetition of one unit p times recovers Q31's zero polynomial.
    assert all(3*finite_unit(0,(t,),3) % 3 == 0 for t in range(3))
    # Fixed bad positions (counts 2,1) vanish at one shared weight challenge.
    zeros = [t for t in range(3) if (2*(1-t)+t) % 3 == 0]
    assert zeros == [2]
    assert len(zeros)*3 != len(zeros)**2  # shared event is 1/3, not 1/9
    for p in (3,5,7):
        alphas = [a for a in range(p) if a not in (0,2)]
        residual = lambda t,a: ((p-1)*(1-t)+t)*pow(a-2,-1,p) % p
        shared = sum(residual(t,a) == residual(t,b) == 0
                     for t,a,b in product(range(p),alphas,alphas))
        independent = sum(residual(t,a) == residual(u,b) == 0
                          for t,u,a,b in product(range(p),range(p),alphas,alphas))
        assert shared == independent == len(alphas)**2
        # The denominators have p versus p^2 unit choices: 1/p versus 1/p^2.
    # Choosing bad positions after theta always finds a cancelling nonempty set.
    for p in (3,5,7):
        for t in range(p):
            counts = (t,(t-1) % p)
            assert any(counts) and all(n < p for n in counts)
            assert (counts[0]*(1-t)+counts[1]*t) % p == 0
    # Late table coefficients can fit one evaluated equation for an invalid value.
    for alpha in (1,3,4):
        coefficient = alpha*pow(alpha-2,-1,5) % 5
        assert pow(alpha-2,-1,5) == coefficient*pow(alpha,-1,5) % 5
    print(f'{cases} nonempty subset cases / {roots_checked} challenge points; degree bounds and schedule counterexamples pass')


def folded(values, point):
    for r in point:
        values = fold(values,r)
    return values[0]


def pair_sum(leaves,d):
    result = (scalar(0,d),scalar(1,d))
    for a,b in leaves:
        c,e = result
        result = (add(mul(c,b),mul(a,e)),mul(e,b))
    return result


def check_preparation():
    rng = random.Random(310731)
    cases = total_reads = 0
    for d in (4,8):
        for case in range(200):
            m = case % 7
            b = case % (min(m,3)+1)
            h,groups = m-b,1 << (m-b)
            table = [(i,(i*i+3) % P) for i in range(1+case % 5)]
            theta = [tuple(rng.randrange(P) for _ in range(d)) for _ in range(h)]
            if case % 11 == 0:
                theta = [scalar(rng.randrange(2),d) for _ in range(h)]
            records = [(rng.randrange(2),rng.choice(table)) for _ in range(1 << m)]
            source = weighted.Source(records)
            mu,stats = weighted.prepare(source,table,m,b,theta,d)
            # Independent histogram over each table value, then half-table MLE folds.
            expected = []
            for t in table:
                counts = [sum(s and value == t for s,value in records[g << b:(g+1) << b])
                          for g in range(groups)]
                expected.append(folded([scalar(n,d) for n in counts],theta))
            assert list(mu) == expected
            assert source.reads == len(records) and source.visits == 1
            assert stats == dict(reads=len(records),increments=sum(s for s,_ in records),
                                 scan_slots=groups*len(table),unit_products=groups*h,
                                 count_slots=len(table),multiplicity_slots=len(table),
                                 accumulator_updates=groups*len(table))
            # Two independently supplied unit points share the same source visit.
            second = [tuple(rng.randrange(P) for _ in range(d)) for _ in range(h)]
            paired_source = weighted.Source(records)
            pair,paired_stats = weighted.prepare_many(paired_source,table,m,b,[theta,second],d)
            assert pair[0] == mu and paired_source.reads == len(records) and paired_source.visits == 1
            assert paired_stats == dict(stats,unit_products=2*groups*h,
                                        multiplicity_slots=2*len(table),accumulator_updates=2*groups*len(table))
            for t,actual in zip(table,pair[1]):
                counts = [sum(s and value == t for s,value in records[g << b:(g+1) << b])
                          for g in range(groups)]
                assert actual == folded([scalar(n,d) for n in counts],second)
            beta = tuple(rng.randrange(P) for _ in range(d))
            alpha = tuple(rng.randrange(P) for _ in range(d))
            denominator = lambda x: add(alpha,neg(add(scalar(x[0],d),mul(beta,scalar(x[1],d)))))
            # Direct per-position numerator uses independently folded indicators.
            weights = [folded([scalar(int(j==g),d) for j in range(groups)],theta)
                       for g in range(groups)]
            left = pair_sum([(weights[i >> b],denominator(x)) if s else (scalar(0,d),scalar(1,d))
                             for i,(s,x) in enumerate(records)],d)
            leaves = [(scalar(s,d),denominator(x)) if s else (scalar(0,d),scalar(1,d)) for s,x in records]
            assert weighted.unit_tree(leaves,b,theta,d) == left
            right = pair_sum([(v,denominator(t)) for v,t in zip(mu,table)],d)
            assert left[1] != scalar(0,d) and right[1] != scalar(0,d)
            assert mul(left[0],right[1]) == mul(right[0],left[1])
            altered = list(mu)
            altered[0] = add(altered[0],scalar(1,d))
            wrong = pair_sum([(v,denominator(t)) for v,t in zip(altered,table)],d)
            assert mul(left[0],wrong[1]) != mul(wrong[0],left[1])
            cases += 1
            total_reads += source.reads
    assert cases == 400
    return cases,total_reads


def rejects(reason, call):
    try:
        call()
    except ValueError as e:
        assert str(e) == reason
    else:
        raise AssertionError(reason)


def check():
    check_subsets()
    cases,reads = check_preparation()
    original = weighted.unit
    for mutant in (lambda g,point,d: scalar(1,d),
                   lambda g,point,d: original(g,list(reversed(point)),d)):
        weighted.unit = mutant
        try:
            check_preparation()
        except AssertionError:
            pass
        else:
            raise AssertionError('unit mutant survived')
        finally:
            weighted.unit = original
    original_tree = weighted.unit_tree
    weighted.unit_tree = lambda leaves,b,point,d: original_tree(leaves,b,list(reversed(point)),d)
    try:
        check_preparation()
    except AssertionError:
        pass
    else:
        raise AssertionError('tree coordinate mutant survived')
    finally:
        weighted.unit_tree = original_tree
    rejects('Shape',lambda: weighted.unit_tree([(scalar(0,4),scalar(1,4))]*3,0,[],4))
    rejects('Shape',lambda: weighted.shape(31,31))
    rejects('Shape',lambda: weighted.shape(1,2))
    rejects('Table',lambda: weighted.prepare(weighted.Source([]),[(0,),(0,)],0,0,[],4))
    rejects('Point',lambda: weighted.prepare(weighted.Source([]),[(0,)],1,0,[(P,0,0,0)],4))
    rejects('Point',lambda: weighted.prepare_many(weighted.Source([]),[(0,)],0,0,[],4))
    rejects('SourceLength',lambda: weighted.prepare(weighted.Source([]),[(0,)],0,0,[],4))
    rejects('Selector',lambda: weighted.prepare(weighted.Source([(2,(0,))]),[(0,)],0,0,[],4))
    rejects('OutsideTable',lambda: weighted.prepare(weighted.Source([(1,(1,))]),[(0,)],0,0,[],4))
    source = weighted.Source([(0,(1,))])
    weighted.prepare(source,[(0,)],0,0,[],4)
    rejects('SourceReused',lambda: weighted.prepare(source,[(0,)],0,0,[],4))
    assert weighted.shape(37,30) == (1 << 37,1 << 30,128,7)
    print(f'{cases} full-K single and paired preparations; {reads} logical reads per mode; changed multiplicities disagree')
    print('three unit/tree mutants and malformed/source cases rejected; no native pass-count, privacy, NC or profile claim')


if __name__ == '__main__':
    check()
