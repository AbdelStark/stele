# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0003 §2/A1 differential arithmetic and complete public proof parity."""
import copy
import hashlib
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cqis-bounds'))
import wide_range as r
from check_wide_range import rejects

sc = r.sc
FIXTURE = Path(__file__).with_name('field-proof-digests.json')


def original(a, b):
    """Independent original schoolbook tower; never calls the candidate."""
    d = len(a)
    if d == 1:
        return (a[0] * b[0] % sc.P,)
    h = d // 2
    ac, bd = original(a[:h], b[:h]), original(a[h:], b[h:])
    nr = {2: (sc.P-1,), 4: (2, 1), 8: (0, 0, 1, 0)}[d]
    plus = lambda x, y: tuple((u+v) % sc.P for u, v in zip(x, y))
    return plus(ac, original(nr, bd)) + plus(original(a[:h], b[h:]), original(a[h:], b[:h]))


def vectors():
    rng = random.Random(2757)
    digest = hashlib.sha256()
    count = 0
    for d in (1, 2, 4, 8):
        boundary = [sc.scalar(x, d) for x in (0, 1, 2, sc.P-1)]
        boundary += [tuple(sc.P-1 if j == k else 0 for j in range(d)) for k in range(d)]
        boundary += [(sc.P-1,)*d, tuple(range(d))]
        pairs = [(a, b) for a in boundary for b in boundary]
        pairs += [(tuple(rng.randrange(sc.P) for _ in range(d)),
                   tuple(rng.randrange(sc.P) for _ in range(d))) for _ in range(10000)]
        for a, b in pairs:
            product = sc.mul(a, b)
            assert product == original(a, b) == sc.mul(b, a)
            assert len(product) == d and all(0 <= x < sc.P for x in product)
            digest.update(sc.encode(product)); count += 1
        for _ in range(100):
            a, b, c = [tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(3)]
            assert sc.mul(sc.mul(a, b), c) == sc.mul(a, sc.mul(b, c))
            assert sc.mul(a, sc.add(b, c)) == sc.add(sc.mul(a, b), sc.mul(a, c))
            for scalar in (0, 1, 2, sc.P-1):
                assert sc.mul(sc.scalar(scalar, d), a) == tuple(scalar*x % sc.P for x in a)
        print('field vectors passed', d, len(pairs), flush=True)
    assert count == 40409 and digest.hexdigest() == 'a31db4088c27b9132d01bdac99b76e1c2b08c045c30ee7cae0a90e1eb48a794c'
    print(json.dumps(dict(seed=2757, products=count, sha256=digest.hexdigest()), sort_keys=True), flush=True)


def canonical(value):
    """Lossless tagged JSON for research artifacts, not a production wire format."""
    if type(value) is bytes:
        return ['bytes', value.hex()]
    if type(value) is dict:
        pairs = [[canonical(k), canonical(v)] for k, v in value.items()]
        return ['dict', sorted(pairs, key=lambda pair: json.dumps(pair[0], separators=(',', ':')))]
    if type(value) in (list, tuple):
        return [type(value).__name__, [canonical(x) for x in value]]
    assert value is None or type(value) in (str, int, bool), type(value)
    return value


def encoded(value):
    return json.dumps(canonical(value), separators=(',', ':'), ensure_ascii=True).encode()


def case(repetitions=1):
    return r.Spec(2757, 29, (0, 257, (1 << 31)+1), repetitions), [0, 256, (1 << 31)+1]


def prepare(repetitions=1):
    p, values = case(repetitions)
    words, bs, cs = r.witness(p, values)
    return p, words, bs, cs, r.source_root(p, words)


def consume(p, root, proof, state, d):
    out = r.verify(p, root, proof, d)
    assert out['state'] == state
    a, b, n, width, _, _ = r.derive(p, d)
    m = a+b+1
    f = lambda x: 3*x*(x-1)//2+2*x
    assert out['account'] == dict(identity_numerator=2*width*n+255,
        identity_power=p.repetitions, lookup_reduction_numerator=p.repetitions*(f(m)+f(8)+3*m),
        range_reduction_numerator=9*a+7*b, denominator=sc.P**d)
    return out


def controls(p, root, proof, d):
    rejects('CommitmentMismatch', lambda: r.verify(p, bytes(32), proof, d))
    bad = copy.deepcopy(proof)
    bad['zero'][0]['final'][0][0] = (sc.P,)+(0,)*(d-1)
    rejects('SourceCopy:NoncanonicalField', lambda: r.verify(p, root, bad, d))
    return 2


def artifact(root, proof, out):
    return hashlib.sha256(encoded((root, proof, out))).hexdigest()


def proofs(capture=False):
    actual = {}
    for d in (4, 8):
        for reps in (1, 2):
            p, words, bs, cs, root = prepare(reps)
            proof, state = r.assemble(p, words, bs, cs, d)
            out = consume(p, root, proof, state, d)
            controls(p, root, proof, d)
            actual[f'{d}/{reps}'] = artifact(root, proof, out)
            print('complete wide proof passed', d, reps, actual[f'{d}/{reps}'], flush=True)
    if capture:
        with FIXTURE.open('x') as stream:
            json.dump(actual, stream, indent=2); stream.write('\n')
    else:
        assert actual == json.loads(FIXTURE.read_text())


if __name__ == '__main__':
    modes = {'--vectors': vectors, '--proofs': proofs, '--capture': lambda: proofs(True)}
    selected = sys.argv[1:] or ['--vectors', '--proofs']
    assert all(mode in modes for mode in selected)
    for mode in selected:
        modes[mode]()
