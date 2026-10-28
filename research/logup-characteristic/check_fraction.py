# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q31 closed public fraction reductions; no native lookup, PCS, ZK or NC credit."""
import copy
import json
from pathlib import Path
import random
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as sc
import fraction as ft
from weighted import unit_tree


def public(s,leaves,d,extra=b''):
    return b'Q31/fraction-study/v1'+ft.descriptor(s,d)+b''.join(sc.encode(v) for row in leaves for v in row)+extra


def evaluate(values,point):
    for x in point:
        values = sc.fold(values,x)
    return values[0]


def rejects(reason,call):
    try:
        call()
    except ValueError as e:
        assert str(e) == reason,(reason,str(e))
    else:
        raise AssertionError(f'accepted instead of {reason}')


def check_trees():
    rng = random.Random(310803)
    cases = 0
    for d in (4,8):
        for case in range(80):
            m = case % 5
            b = case % (m+1)
            rand = lambda: tuple(rng.randrange(sc.P) for _ in range(d))
            s = dict(id=case,m=m,b=b,leaves=(11,12),theta=[rand() for _ in range(m-b)])
            if case % 7 == 0:
                s['theta'] = [sc.scalar(rng.randrange(2),d) for _ in s['theta']]
            leaves = [(rand(),rand()) for _ in range(1 << m)]
            context = public(s,leaves,d)
            pt,vt = ft.Transcript(context,d),ft.Transcript(context,d)
            proof,pr = ft.prove(pt,s,leaves)
            vr = ft.verify(vt,s,proof)
            ft.consume(vr,leaves,d)
            assert proof['root'] == unit_tree(leaves,b,s['theta'],d)
            assert pr == vr and pt.state == vt.state
            assert vr['values'] == tuple(evaluate([row[j] for row in leaves],vr['point']) for j in range(2))
            assert vr['ids'] == s['leaves'] and len(vr['point']) == m
            assert [r['numerator'] for r in vr['sc']] == [3*k for k in range(m)]
            assert vr['numerator'] == 3*m*(m-1)//2+2*m
            assert len(ft.proof_bytes(s,proof,d)) == 4*d*(2+2*m*m+3*m)
            assert sc.challenge(pt) == sc.challenge(vt)
            wrong = copy.deepcopy(proof)
            wrong['root'] = (sc.add(wrong['root'][0],sc.scalar(1,d)),wrong['root'][1])
            if m:
                rejects('FinalEvaluationMismatch',lambda: ft.verify(ft.Transcript(context,d),s,wrong))
            else:
                rejects('LeafMismatch',lambda: ft.consume(ft.verify(ft.Transcript(context,d),s,wrong),leaves,d))
            if m >= 2:
                wrong = copy.deepcopy(proof)
                wrong['steps'][1]['rounds'][0][0] = sc.add(wrong['steps'][1]['rounds'][0][0],sc.scalar(1,d))
                rejects('RoundSumMismatch',lambda: ft.verify(ft.Transcript(context,d),s,wrong))
            cases += 1
    assert cases == 160
    return cases


def check_leaf_sources():
    rng = random.Random(310804)
    cases = 0
    for d in (4,8):
        for case in range(40):
            m = case % 4
            rand = lambda: tuple(rng.randrange(sc.P) for _ in range(d))
            sigma = [sc.scalar(rng.randrange(2),d) for _ in range(1 << m)]
            xs = [[sc.scalar(rng.randrange(17),d) for _ in sigma] for _ in range(1+case % 3)]
            alpha,beta = rand(),rand()
            leaves = ft.lookup_leaves(sigma,xs,alpha,beta,d)
            s = dict(id=case,m=m,b=m,leaves=(11,12),theta=[])
            ids = tuple(range(100,100+len(xs)))
            extra = sc.encode(alpha)+sc.encode(beta)+struct.pack('<I',len(xs))+b''.join(
                sc.encode(v) for row in [sigma,*xs] for v in row)
            context = public(s,leaves,d,extra)
            pt,vt = ft.Transcript(context,d),ft.Transcript(context,d)
            tree,pr = ft.prove(pt,s,leaves)
            vr = ft.verify(vt,s,tree)
            leaf,lr = ft.prove_leaf(pt,s,pr,sigma,ids,xs,alpha,beta)
            result = ft.verify_leaf(vt,s,vr,sigma,ids,leaf,alpha,beta)
            ft.consume_sources(result,ids,xs,d)
            assert result == lr and pt.state == vt.state
            assert result['sc']['numerator'] == 3*m
            assert [identity for identity,_ in result['claims']] == list(ids)
            for source,(_,value) in zip(xs,result['claims']):
                assert value == evaluate(source,result['point'])
            cases += 1
    assert cases == 80
    # MLE of a selected product is different from multiplying separate MLEs.
    d = 4
    sigma,x = [sc.scalar(v,d) for v in (1,0)],[sc.scalar(v,d) for v in (0,1)]
    r,alpha,beta = [sc.scalar(2,d)],sc.scalar(7,d),sc.scalar(3,d)
    leaves = ft.lookup_leaves(sigma,[x],alpha,beta,d)
    true_q = evaluate([q for _,q in leaves],r)
    separate = sc.add(sc.scalar(1,d),sc.mul(evaluate(sigma,r),sc.add(sc.add(alpha,sc.scalar(-1,d)),sc.neg(evaluate(x,r)))))
    assert true_q != separate
    return cases


def check_boundaries():
    d = 4
    zero,one = sc.scalar(0,d),sc.scalar(1,d)
    s = dict(id=1,m=1,b=1,leaves=(11,12),theta=[])
    leaves = [(zero,zero)]*2
    context = public(s,leaves,d)
    proof,_ = ft.prove(ft.Transcript(context,d),s,leaves)
    wrong = copy.deepcopy(proof)
    wrong['steps'][0]['final'][4] = sc.scalar(2,d)
    rejects('CoefficientMismatch',lambda: ft.verify(ft.Transcript(context,d),s,wrong))
    wrong = copy.deepcopy(proof)
    wrong['steps'][0]['final'][0] = one
    receipt = ft.verify(ft.Transcript(context,d),s,wrong)
    rejects('LeafMismatch',lambda: ft.consume(receipt,leaves,d))
    early = ft.Transcript(context,d)
    early.bind(ft.TREE,ft.descriptor(s,d)+ft.fields(proof['root'],d))
    instance = ft.layer(early,s,0,[],proof['root'])
    early.absorb(sc.INSTANCE,sc.instance_bytes(instance,d))
    stale = early.draw(ft.FOLD)  # An adversary chooses children after an early draw.
    wrong = copy.deepcopy(proof)
    wrong['steps'][0]['final'][0] = stale
    wrong['steps'][0]['final'][2] = sc.add(stale,sc.neg(one))
    receipt = ft.verify(ft.Transcript(context,d),s,wrong)
    rejects('LeafMismatch',lambda: ft.consume(receipt,leaves,d))
    stale = ft.Transcript(context,d).draw(ft.GAMMA)
    wrong = copy.deepcopy(proof); wrong['root'] = (sc.neg(stale),one)
    rejects('FinalEvaluationMismatch',lambda: ft.verify(ft.Transcript(context,d),s,wrong))
    rejects('Pole',lambda: ft.root_equation(proof['root'],(zero,one),d))
    rejects('NoncanonicalField',lambda: ft.root_equation((list(zero),list(zero)),(zero,one),d))
    rejects('RootMismatch',lambda: ft.root_equation((one,one),(zero,one),d))
    ft.root_equation((one,one),(sc.scalar(2,d),sc.scalar(2,d)),d)
    wrong = copy.deepcopy(proof); wrong['steps'].append(wrong['steps'][0])
    rejects('TreeShape',lambda: ft.verify(ft.Transcript(context,d),s,wrong))
    wrong = copy.deepcopy(proof); wrong['root'] = ((sc.P,0,0,0),zero)
    rejects('NoncanonicalField',lambda: ft.verify(ft.Transcript(context,d),s,wrong))

    # Every source claim remains an obligation even when its coefficient is zero.
    sigma,xs,ids = [zero,zero],[[zero,zero],[zero,zero]],(100,101)
    alpha,beta = sc.scalar(7,d),zero
    leaves = ft.lookup_leaves(sigma,xs,alpha,beta,d)
    context = public(s,leaves,d,ft.fields([alpha,beta,*sigma,*xs[0],*xs[1]],d))
    pt = ft.Transcript(context,d)
    tree,original = ft.prove(pt,s,leaves)
    leaf,_ = ft.prove_leaf(pt,s,original,sigma,ids,xs,alpha,beta)

    def verify_leaf(candidate):
        vt = ft.Transcript(context,d)
        original = ft.verify(vt,s,tree)
        return ft.verify_leaf(vt,s,original,sigma,ids,candidate,alpha,beta)

    for index,reason in ((0,'CoefficientMismatch'),(1,'SelectorMismatch')):
        wrong = copy.deepcopy(leaf)
        wrong['final'][index] = sc.add(wrong['final'][index],one)
        rejects(reason,lambda: verify_leaf(wrong))
    wrong = copy.deepcopy(leaf); wrong['final'][-1] = one
    reduced = verify_leaf(wrong)
    rejects('SourceMismatch',lambda: ft.consume_sources(reduced,ids,xs,d))
    rejects('SourceShape',lambda: ft.consume_sources(reduced,ids[::-1],xs,d))
    bad_selector = [sc.scalar(2,d),zero]
    rejects('Selector',lambda: ft.lookup_leaves(bad_selector,xs,alpha,beta,d))
    bad = {**s,'theta':[zero]}
    rejects('TreeShape',lambda: ft.descriptor(bad,d))


def codec_vectors():
    """Actual Python tree proofs, plus independently described field order."""
    rng = random.Random(310809)
    result = []
    for d in (4,8):
        for m in (0,1,3):
            for b in sorted({0,m//2,m}):
                rand = lambda: tuple(rng.randrange(sc.P) for _ in range(d))
                identity = len(result)+31 if d == 4 else (1 << 64)-1-len(result)
                s = dict(id=identity,m=m,b=b,leaves=(101,(1 << 63)+102),theta=[rand() for _ in range(m-b)])
                leaves = [(rand(),rand()) for _ in range(1 << m)]
                proof,_ = ft.prove(ft.Transcript(public(s,leaves,d),d),s,leaves)
                encoded = lambda values: [sc.encode(x).hex() for x in values]
                result.append(dict(degree=d,descriptor={**s,'leaves':list(s['leaves']),'theta':encoded(s['theta'])},
                    descriptor_hex=ft.descriptor(s,d).hex(),payload_hex=ft.proof_bytes(s,proof,d).hex(),
                    proof=dict(root=encoded(proof['root']),steps=[dict(rounds=[encoded(row) for row in step['rounds']],
                        final=encoded(step['final'])) for step in proof['steps']])))
    return result


def check_codec_vectors(write=False):
    path = Path(__file__).resolve().parents[2] / 'crates/stele-lookup/tests/fixtures/fraction-codec.jsonl'
    records = codec_vectors()
    if write:
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('x') as output:
            output.write(''.join(json.dumps(record,separators=(',',':'))+'\n' for record in records))
    else:
        assert [json.loads(line) for line in path.read_text().splitlines()] == records
    assert len(records) == 12
    print('12 both-field native codec fixtures match actual Python proofs; no native proof verification credit')


if __name__ == '__main__':
    if sys.argv[1:] in (['--codec'],['--write-codec']):
        check_codec_vectors(sys.argv[1:] == ['--write-codec'])
        raise SystemExit(0)
    assert not sys.argv[1:]
    trees,leaves = check_trees(),check_leaf_sources()
    check_boundaries()
    check_codec_vectors()
    print(f'{trees} full-K fraction trees and {leaves} selector/source reductions: claims, bytes, accounting and continuation agree')
    print('root/round/coefficient/leaf/pole/malformed controls reject; no native NC, PCS, ZK or profile credit')
