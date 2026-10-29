# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0008 A3: shared conditional public decisions, not lookup acceptance."""
import copy
import json
from pathlib import Path
import struct
import sys
import check_fraction as reference

ft, sc = reference.ft, reference.sc
PATH = Path(__file__).with_name('corpus.jsonl')


def value(raw, d):
    raw = bytes.fromhex(raw)
    ft.require(len(raw) == 4*d, 'NoncanonicalField')
    result = struct.unpack('<'+'I'*d, raw)
    ft.field(result, d)
    return result


def decode(raw, d, counts):
    """Length before limbs; counts come exclusively from the fixed descriptor."""
    raw = bytes.fromhex(raw)
    ft.require(len(raw) == 4*d*sum(counts), 'ProofShape')
    values = [value(raw[i:i+4*d].hex(), d) for i in range(0, len(raw), 4*d)]
    rows, cursor = [], 0
    for count in counts:
        rows.append(values[cursor:cursor+count])
        cursor += count
    return rows


def verify(c):
    d, s = c['degree'], copy.deepcopy(c['descriptor'])
    m = s['m']
    s['theta'] = [value(v, d) for v in s['theta']]
    s['leaves'] = tuple(s['leaves'])
    ft.descriptor(s, d)
    leaves = [[value(v, d) for v in row] for row in c['leaves']]
    rows = iter(decode(c['tree'], d, [2]+[n for k in range(m) for n in [4]*k+[5]]))
    proof = dict(root=next(rows), steps=[dict(rounds=[next(rows) for _ in range(k)], final=next(rows)) for k in range(m)])
    t = ft.Transcript(bytes.fromhex(c['public']), d)
    tree = ft.verify(t, s, proof)
    ft.consume(tree, leaves, d)
    if 'right' in c:
        ft.root_equation(proof['root'], [value(v, d) for v in c['right']], d)
    encoded = lambda vs: [sc.encode(v).hex() for v in vs]
    output = dict(tree=dict(point=encoded(tree['point']), claims=list(zip(tree['ids'], encoded(tree['values']))),
        accounting=dict(tree_id=s['id'], field_degree=d, gamma=m, fold=m, layers=tree['sc']), numerator=tree['numerator']))
    if 'leaf' in c:
        leaf = c['leaf']
        ids = leaf['sources']
        sigma = [value(v, d) for v in leaf['sigma']]
        xs = [[value(v, d) for v in col] for col in leaf['xs']]
        alpha, beta = value(leaf['alpha'], d), value(leaf['beta'], d)
        rows = decode(leaf['proof'], d, [4]*m+[len(ids)+2])
        selected = dict(rounds=rows[:-1], final=rows[-1])
        result = ft.verify_leaf(t, s, tree, sigma, ids, selected, alpha, beta)
        ft.consume_sources(result, ids, xs, d)
        output['leaf'] = dict(tree_id=s['id'], point=encoded(result['point']),
            claims=[[i, sc.encode(v).hex()] for i, v in result['claims']], sc=result['sc'])
    # Expected decisions never enter either verifier. Reproving is an extra parity check.
    if c['expected'] == 'accept':
        pt = ft.Transcript(bytes.fromhex(c['public']), d)
        produced, original = ft.prove(pt, s, leaves)
        assert ft.proof_bytes(s, produced, d).hex() == c['tree'] and original == tree
        if 'leaf' in c:
            produced, receipt = ft.prove_leaf(pt, s, original, sigma, ids, xs, alpha, beta)
            assert produced == selected and receipt == result
        assert pt.state == t.state
    output['continuation'] = sc.encode(sc.challenge(t)).hex()
    return output


def decision(c):
    try:
        output = verify(c)
    except ValueError as error:
        output = dict(error=str(error))
    return dict(name=c['name'], **output)


def bump(raw, d, index=0):
    size = 8*d
    start = index*size
    changed = sc.encode(sc.add(value(raw[start:start+size], d), sc.scalar(1, d))).hex()
    return raw[:start]+changed+raw[start+size:]


def corpus():
    cases = []
    def add(base, name, expected='accept'):
        c = copy.deepcopy(base)
        c.update(name=f"{base['name']}/{name}", expected=expected)
        cases.append(c)
        return c

    def malformed(base, leaf=False):
        for label, expected in [('short','ProofShape'), ('trailing','ProofShape'), ('limb','NoncanonicalField')]:
            c = add(base, label, expected)
            obj, key = (c['leaf'], 'proof') if leaf else (c, 'tree')
            raw = obj[key]
            obj[key] = raw[:-2] if label == 'short' else raw+'00' if label == 'trailing' else 'ffffff7f'+raw[8:]

    for j, row in enumerate(reference.codec_vectors()):
        d, m = row['degree'], row['descriptor']['m']
        base = dict(name=f'tree-{j}', degree=d, descriptor=row['descriptor'], public=row['public'], leaves=row['leaves'], tree=row['payload_hex'])
        add(base, 'honest')
        malformed(base)
        c = add(base, 'root', 'FinalEvaluationMismatch' if m else 'LeafMismatch')
        c['tree'] = bump(c['tree'], d)
        c = add(base, 'original', 'LeafMismatch')
        c['leaves'][0][0] = bump(c['leaves'][0][0], d)
        if m >= 2:
            c = add(base, 'round', 'RoundSumMismatch')
            c['tree'] = bump(c['tree'], d, 7)
    for j, row in enumerate(reference.leaf_codec_vectors()):
        d, m = row['degree'], row['m']
        base = dict(name=f'leaf-{j}', degree=d, descriptor=dict(id=row['id'], m=m, b=m, leaves=[11,12], theta=[]),
            public=row['public'], leaves=row['leaves'], tree=row['tree_hex'],
            leaf={key:row[key] for key in ('sources','sigma','xs','alpha','beta')})
        base['leaf']['proof'] = row['payload_hex']
        add(base, 'honest')
        malformed(base, True)
        c = add(base, 'original', 'SourceMismatch')
        c['leaf']['xs'][-1][0] = bump(c['leaf']['xs'][-1][0], d)
        if m:
            c = add(base, 'round', 'RoundSumMismatch')
            c['leaf']['proof'] = bump(c['leaf']['proof'], d)
    for d in (4,8):
        scalar = lambda v: sc.scalar(v,d)
        enc = lambda vs: [sc.encode(v).hex() for v in vs]
        s = dict(id=900+d, m=1, b=1, leaves=(11,12), theta=[])
        sigma, xs, alpha, beta = list(map(scalar,[1,0])), [list(map(scalar, col)) for col in [[0,0],[7,11]]], scalar(19), scalar(0)
        leaves = ft.lookup_leaves(sigma,xs,alpha,beta,d)
        context = reference.public(s,leaves,d)
        t = ft.Transcript(context,d)
        proof, receipt = ft.prove(t,s,leaves)
        selected, _ = ft.prove_leaf(t,s,receipt,sigma,[91,92],xs,alpha,beta)
        base = dict(name=f'zero-{d}', degree=d, descriptor=s, public=context.hex(), leaves=[enc(row) for row in leaves],
            tree=ft.proof_bytes(s,proof,d).hex(), leaf=dict(sources=[91,92], sigma=enc(sigma), xs=[enc(col) for col in xs],
            alpha=enc([alpha])[0], beta=enc([beta])[0], proof=b''.join(ft.fields(row,d) for row in [*selected['rounds'],selected['final']]).hex()))
        add(base, 'honest')
        for label, index, expected in [('coefficient',4,'CoefficientMismatch'), ('selector',5,'SelectorMismatch'), ('unused-source',7,'SourceMismatch')]:
            c = add(base,label,expected)
            c['leaf']['proof'] = bump(c['leaf']['proof'],d,index)
        for label, q, right, expected in [('honest',1,[6,2],'accept'), ('left-pole',0,[3,1],'Pole'),
                                         ('right-pole',1,[1,0],'Pole'), ('unequal',1,[4,1],'RootMismatch')]:
            s = dict(id=950+d,m=0,b=0,leaves=(11,12),theta=[])
            leaves = [list(map(scalar,[3,q]))]
            context = reference.public(s,leaves,d)
            proof, _ = ft.prove(ft.Transcript(context,d),s,leaves)
            base = dict(name=f'root-{d}',degree=d,descriptor=s,public=context.hex(),leaves=[enc(row) for row in leaves],
                        tree=ft.proof_bytes(s,proof,d).hex(),right=enc(list(map(scalar,right))))
            add(base,label,expected)
    assert len(cases) == 162 and len({c['name'] for c in cases}) == len(cases)
    for c in cases:
        actual = decision(c).get('error','accept')
        assert actual == c['expected'], (c['name'],c['expected'],actual)
    return cases


if __name__ == '__main__':
    if sys.argv[1:] == ['--write']:
        with PATH.open('x') as output:
            output.write(''.join(json.dumps(c,separators=(',',':'))+'\n' for c in corpus()))
    elif sys.argv[1:] == ['--check']:
        assert [json.loads(line) for line in PATH.read_text().splitlines()] == json.loads(json.dumps(corpus()))
        print('162 fraction corpus cases regenerated with declared decisions')
    else:
        assert len(sys.argv) == 2
        for line in Path(sys.argv[1]).read_text().splitlines():
            print(json.dumps(decision(json.loads(line)),separators=(',',':')))
