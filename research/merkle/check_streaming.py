# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0012 A3: stored/streamed roots and complete revealing lookup parity."""
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import check_merkle as merkle

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'logup-characteristic'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import lookup as lu


class Once:
    """No length, random access or second traversal of the input stream."""
    def __init__(self, values):
        self.values = iter(values)
        self.started = False

    def __iter__(self):
        assert not self.started, 'second input pass'
        self.started = True
        return self

    def __next__(self):
        return next(self.values)


def matches_reference_vectors():
    vectors = [json.loads(line) for line in Path(__file__).with_name('vectors.jsonl').read_text().splitlines()]
    for vector in vectors:
        tree = merkle.Tree(**vector['tree'])
        leaves = [bytes.fromhex(x) for x in vector['leaves']]
        root = merkle.root(tree, Once(leaves))
        assert root.hex() == vector['root']
        for index, payload in enumerate(leaves):
            path = [bytes.fromhex(x) for x in vector['paths'][index]]
            merkle.verify(tree, root, index, payload, path)
            merkle.rejects('RootMismatch', lambda: merkle.verify(tree, merkle.flip(root), index, payload, path))
    assert len(vectors) == 10


def rejects_malformed_streams():
    for count in (1, 2, 3, 4, 5, 17):
        tree = merkle.Tree(0, 17, count, 4)
        leaves = [struct.pack('<I', i) for i in range(count)]
        for bad in (leaves[:-1], leaves + [b'\0'*4], leaves[:count-1] + [b'\0'*3], []):
            merkle.rejects('InvalidLeaf', lambda: merkle.root(tree, Once(bad)))
        root = merkle.root(tree, Once(leaves))
        assert root != merkle.root(replace(tree, id=18), Once(leaves))
        if count > 1:
            assert root != merkle.root(tree, Once(reversed(leaves)))
        # A real zero payload is not an absent padding leaf.
        if count & (count - 1):
            size = 1 << tree.height()
            assert root != merkle.root(replace(tree, count=size), Once(leaves + [bytes(4)]*(size-count)))
    tree = merkle.Tree(0, 17, 1, 4)
    for bad in (replace(tree, kind=1), replace(tree, count=0), replace(tree, width=0),
                replace(tree, id=1 << 64), replace(tree, count=(1 << 63)+1), replace(tree, kind=2)):
        merkle.rejects('InvalidTree', lambda: merkle.root(bad, Once([bytes(4)])))


def matches_reference_corpus():
    rng = random.Random(2758)
    digest = hashlib.sha256()
    leaves_checked = 0
    cases = [(rng.choice((0, 2)), rng.getrandbits(64), rng.randrange(1, 258), rng.choice((1, 4, 8, 16, 32))) for _ in range(10000)]
    cases += [(kind, (1 << 64)-1, n, 4) for kind in (0, 2) for n in (65535, 65536, 65537, 131071, 131072, 131073)]
    for case, (kind, identity, count, width) in enumerate(cases):
        tree = merkle.Tree(kind, identity, count, 32 if kind == 2 else width)
        leaves = [hashlib.shake_256(struct.pack('<II', case, i)).digest(tree.width) for i in range(count)]
        expected = merkle.build(tree, leaves)[-1][0]
        actual = merkle.root(tree, Once(leaves))
        assert actual == expected, (case, tree)
        digest.update(tree.header() + actual)
        leaves_checked += count
        if (case+1) % 1000 == 0 or case >= 10000:
            print('root parity passed', case+1, count, flush=True)
    assert (len(cases), leaves_checked, digest.hexdigest()) == (10012, 2478160, '3825ffbe517f7956214fec8d629028f07ecc39b86897e82e6234bfeb760f6e22')
    print(json.dumps(dict(seed=2758, cases=len(cases), leaves=leaves_checked, sha256=digest.hexdigest()), sort_keys=True), flush=True)


def proof_digests():
    records = {}
    for d in (4, 8):
        for repetitions in (1, 2):
            plan = dict(id=2758, m=2, b=1, r=repetitions, sources=(100, 101),
                        mus=tuple(range(200, 200+repetitions)), table=((0, 1), (7, 9), (15, 255)), sigma=(1, 0, 1, 1))
            sources = [[0, 1234, 7, 15], [1, 5678, 9, 255]]
            roots = lu.source_roots(plan, sources)
            proof, receipt = lu.prove(plan, sources, d)
            verified = lu.verify(plan, roots, proof, d)
            assert verified == receipt
            for index in range(2):
                bad_roots = roots.copy()
                bad_roots[index] = merkle.flip(bad_roots[index])
                merkle.rejects('FinalEvaluationMismatch', lambda: lu.verify(plan, bad_roots, proof, d))
                bad = copy.deepcopy(proof)
                bad['sources'][index][0] += 1
                merkle.rejects('CommitmentMismatch', lambda: lu.verify(plan, roots, bad, d))
            def encode_bytes(value):
                assert type(value) is bytes
                return {'bytes': value.hex()}
            # Test-only serialization of the full proof/receipt, not a wire format.
            encoded = json.dumps(dict(plan=plan, roots=roots, proof=proof, receipt=receipt),
                                 default=encode_bytes, sort_keys=True, separators=(',', ':')).encode()
            records[f'{d}/{repetitions}'] = hashlib.sha256(encoded).hexdigest()
            print('complete lookup parity', d, repetitions, records[f'{d}/{repetitions}'], flush=True)
    return records


def matches_reference_proofs():
    expected = json.loads(Path(__file__).with_name('streaming-proof-digests.json').read_text())
    assert proof_digests() == expected


if __name__ == '__main__':
    modes = {'--corpus': lambda: (matches_reference_vectors(), rejects_malformed_streams(), matches_reference_corpus()),
             '--proofs': matches_reference_proofs}
    assert all(mode in modes for mode in sys.argv[1:])
    for mode in sys.argv[1:] or modes:
        modes[mode]()
