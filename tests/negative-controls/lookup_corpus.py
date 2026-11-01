# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0008 A5: independent producer and closed-consumer bytes/records/usage."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
from blake3 import blake3 as raw_hash
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
for folder in ('merkle-oracle', 'logup-characteristic', 'cqis-tables'):
    sys.path.insert(0, str(ROOT/'research'/folder))
import field_wire as pcs
import fraction as ft
import table_identity as ti
assert ft.sc is pcs.sc
assert Path(pcs.sc.__file__).resolve() == ROOT/'research/sumcheck/check_sumcheck.py'
for module, path in ((pcs, 'merkle-oracle/field_wire.py'), (ft, 'logup-characteristic/fraction.py'), (ti, 'cqis-tables/table_identity.py')):
    assert Path(module.__file__).resolve() == ROOT/'research'/path
sc = pcs.sc
PREFIX = b'stele/v0.1/lookup/'
STATEMENT, UNITS, MULTIPLICITIES, REPETITION, CLAIMS, UNIT, BETA, ALPHA = (
    PREFIX+s for s in (b'statement', b'units', b'multiplicities', b'repetition', b'multiplicity-claims', b'unit', b'beta', b'alpha'))
PUBLIC = b'conditional lookup producer corpus/v1'
EXPECTED = 'cb8e5b658bbd7f5ed6c917f36605daf33331a7fa46e12eb31d7584c0d76887c9'
CLOSED_EXPECTED = 'ce40cdb3b09cf153b6f81a4962abe2e8959c38e05f6d71b149a2f486a1574a41'

def hashes():
    return dict(hash_evaluations=0, xof_requests=0, xof_bytes=0, state_updates=0,
                candidate_words=0, column_attempts=0)

CREATED = []
class Transcript(pcs.Transcript):
    """Actual A1 sampler/framing, observing bounded success and RootMismatch prefixes."""
    def __init__(self, public, degree):
        pcs.require(public and degree in (4, 8), 'InvalidTranscript')
        self.degree = degree
        # Keep transcript hashes separate while the local Merkle counter is active.
        self.state = raw_hash(pcs.frame(raw_hash(pcs.INITIAL).digest(), 0, pcs.PUBLIC, public)).digest()
        self.usage = hashes() | dict(hash_evaluations=2, state_updates=1)
        self.public_bytes = len(public)
        self.in_column = False
        self.draws = {}
        CREATED.append(self)

    def absorb(self, label, payload):
        pcs.require(label in (*pcs.ABSORBS, ft.TREE, ft.LAYER, ft.LEAF,
                            STATEMENT, UNITS, MULTIPLICITIES, REPETITION, CLAIMS), 'InvalidAbsorbLabel')
        self.state = raw_hash(pcs.frame(self.state, 0, label, payload)).digest()
        self.usage['hash_evaluations'] += 1
        self.usage['state_updates'] += 1
        self.public_bytes += len(payload)

    def challenge(self, label=pcs.CHALLENGE):
        pcs.require(label in (*pcs.CHALLENGES, ft.GAMMA, ft.FOLD, UNIT, BETA, ALPHA), 'InvalidChallengeLabel')
        old = self.state
        raw = raw_hash(pcs.frame(old, 1, label, bytes([self.degree]))).digest(length=256)
        self.usage['xof_requests'] += 1
        self.usage['xof_bytes'] += 256
        try:
            value, consumed = pcs.sample(raw, self.degree)
        except ValueError as error:
            assert str(error) == 'SamplingExhausted'
            self.usage['candidate_words'] += 64
            raise
        self.usage['candidate_words'] += consumed
        payload = bytes([self.degree])+struct.pack('<I', consumed)+value
        self.state = raw_hash(pcs.frame(old, 2, label, payload)).digest()
        self.usage['hash_evaluations'] += 1
        self.usage['state_updates'] += 1
        self.draws[label] = self.draws.get(label, 0)+1
        return value, consumed

    def field(self, label):
        if self.in_column:
            self.usage['column_attempts'] += 1
        return super().field(label)

    def column(self, label, size):
        self.in_column = True
        try:
            return super().column(label, size)
        finally:
            self.in_column = False

    def bind(self, label, payload): self.absorb(label, payload)
    def draw(self, label): return self.field(label)

@contextmanager
def local_hashes(counter):
    """Observe actual unchanged Table/Merkle/certificate-ID hash calls separately."""
    def counted(*args, **kwargs):
        counter['hash_evaluations'] += 1
        return raw_hash(*args, **kwargs)
    old = pcs.blake3, pcs.merkle.blake3, ti.blake3
    pcs.blake3 = pcs.merkle.blake3 = ti.blake3 = counted
    try:
        yield
    finally:
        pcs.blake3, pcs.merkle.blake3, ti.blake3 = old

def register(source, witness):
    before = len(CREATED)
    proof = pcs.certify(source, witness)
    assert len(CREATED) == before+1
    production = CREATED[-1]
    local = hashes()
    with local_hashes(local):
        handle = pcs.verify_certificate(source, proof)
    assert len(CREATED) == before+2
    verification = CREATED[-1]
    usage = dict(production=production.usage.copy(), verification=dict(
        transcript=verification.usage.copy(), non_transcript=local))
    return handle, proof, usage, production.public_bytes+verification.public_bytes

def statements(case, descriptor, handles):
    d, m, b = case['degree'], case['m'], case['b']
    real, padded, c = ti.shape(descriptor)
    layouts = case['multiplicities']
    result = struct.pack('<BBQBBBBIB', 1, d, case['lookup_id'], m, b, len(layouts), c, real, padded.bit_length()-1)
    for encoded in (ti.encode(descriptor), ti.encode_data(descriptor)):
        result += struct.pack('<I', len(encoded))+encoded
    result += struct.pack('<Q', 1 << m)+bytes(case['selector'])
    result += b''.join(h.source.bytes()+h.identity for h in handles)
    return result+b''.join(struct.pack('<QBB', v['id'], v['ell'], v['blowup']) for v in layouts)

def reference(case):
    d, m, b, identity = (case[k] for k in ('degree', 'm', 'b', 'lookup_id'))
    zero, one = sc.scalar(0, d), sc.scalar(1, d)
    info = case['table']
    descriptor = ti.Descriptor(info['name'], info['version'], bytes.fromhex(info['params_hex']))
    real, n, c = ti.shape(descriptor)
    rows = ti.canonical_rows(descriptor)
    layouts, sources, witnesses, handles, setup = case['multiplicities'], [], [], [], []
    for info in case['originals']:
        width = 1 << (m-info['ell'])
        matrix = [info['message'][i:i+width] for i in range(0, 1 << m, width)]
        source, witness = pcs.commit(matrix, info['ell'], m-info['ell'], info['blowup'], d, info['id'])
        handle, proof, _, _ = register(source, witness)
        sources.append(source); witnesses.append(witness); handles.append(handle)
        setup.append(dict(source=source.bytes().hex(), certificate=proof.hex(), id=handle.identity.hex()))
    t = Transcript(bytes.fromhex(case['public_hex']), d)
    usage = dict(transcript=None, non_transcript=hashes(), registrations=[None, None])
    with local_hashes(usage['non_transcript']):
        statement = statements(case, descriptor, handles)
    result = dict(name=case['name'], degree=d, statement=statement.hex(), originals=setup)
    out, public_before, registration_bytes = bytearray([1, d]), t.public_bytes, 0
    checking_roots = False
    try:
        t.absorb(STATEMENT, statement)
        theta = []
        for j in range(len(layouts)):
            t.absorb(UNITS, struct.pack('<QB', identity, j))
            theta.append([t.field(UNIT) for _ in range(m-b)])
        # Equality-sum definition: unmatched selected tuples stay selected in the
        # actual lookup leaves. weighted.prepare_many's early OutsideTable differs.
        original_tuples = list(zip(*(v['message'] for v in case['originals'])))
        keys = {tuple(v % sc.P for v in row): i for i, row in enumerate(rows[:real])}
        mu = []
        for units in theta:
            histogram = [zero]*n
            for i, values in enumerate(original_tuples):
                row = keys.get(values)
                if case['selector'][i] and row is not None:
                    histogram[row] = sc.add(histogram[row], ft.unit(i >> b, units, d))
            mu.append(histogram)
        if case['name'].startswith('partial'):
            assert any(any(value[1:]) for histogram in mu for value in histogram), 'fixture must exercise nonbase mu'
        prepared_mu, mu_handles = [], []
        bundle = struct.pack('<QB', identity, len(layouts))
        for j, layout in enumerate(layouts):
            column_bits = n.bit_length()-1-layout['ell']+(d.bit_length()-1)
            limbs = [limb for value in mu[j] for limb in value]
            if case.get('physical_tail'):
                assert real < n
                limbs[real*d:] = range(1, (n-real)*d+1)
            width = 1 << column_bits
            matrix = [limbs[i:i+width] for i in range(0, len(limbs), width)]
            with local_hashes(usage['non_transcript']):
                source, witness = pcs.commit(matrix, layout['ell'], column_bits, layout['blowup'], d, layout['id'])
            handle, proof, observed, public = register(source, witness)
            usage['registrations'][j] = observed
            registration_bytes += public
            prepared_mu.append(witness); mu_handles.append(handle)
            bundle += bytes([j])+source.bytes()+handle.identity
            out += source.root+proof
        t.absorb(MULTIPLICITIES, bundle)
        pairs = []
        for j in range(len(layouts)):
            t.absorb(REPETITION, struct.pack('<QBB', identity, j, 0))
            pairs.append((t.field(BETA), t.field(ALPHA)))
        sigma = [sc.scalar(v, d) for v in case['selector']]
        xs = [[sc.scalar(v, d) for v in info['message']] for info in case['originals']]
        for j, (beta, alpha) in enumerate(pairs):
            t.absorb(REPETITION, struct.pack('<QBB', identity, j, 1))
            left = dict(id=4*identity+2*j, m=m, b=b, leaves=(8*identity+4*j, 8*identity+4*j+1), theta=theta[j])
            k = n.bit_length()-1
            right = dict(id=left['id']+1, m=k, b=k, leaves=(left['leaves'][0]+2, left['leaves'][0]+3), theta=[])
            lp, lr = ft.prove(t, left, ft.lookup_leaves(sigma, xs, alpha, beta, d))
            out += ft.proof_bytes(left, lp, d)
            powers = ft.powers(beta, c, d)
            leaves = [(mu[j][i], sc.add(alpha, sc.neg(pcs.dot(powers, [sc.scalar(v, d) for v in row], d)))) if i < real else (zero, one) for i, row in enumerate(rows)]
            rp, rr = ft.prove(t, right, leaves)
            out += ft.proof_bytes(right, rp, d)
            checking_roots = True
            ft.root_equation(lp['root'], rp['root'], d)
            checking_roots = False
            public_columns = [ft.mle([sc.scalar(row[a], d) for row in rows], rr['point'], d) for a in range(c)]
            valid = ft.mle([one]*real+[zero]*(n-real), rr['point'], d)
            expected_q = sc.add(sc.add(one, sc.mul(sc.add(alpha, sc.neg(one)), valid)), sc.neg(pcs.dot(powers, public_columns, d)))
            assert rr['values'][1] == expected_q
            proof, reduction = ft.prove_leaf(t, left, lr, sigma, [s.identity for s in sources], xs, alpha, beta)
            out += pcs.field_bytes([v for row in proof['rounds'] for v in row]+proof['final'])
            for a, (source, handle, witness) in enumerate(zip(sources, handles, witnesses)):
                point = reduction['point']
                out += pcs.open_functional(t, source.identity, handle, witness,
                    pcs.eq(point[:source.ell], d), pcs.eq(point[source.ell:], d), reduction['claims'][a][1])
            source, point = mu_handles[j].source, rr['point']
            width = (1 << source.m)//d
            q, tail = divmod(real, width)
            rows_eq, suffix_eq = pcs.eq(point[:source.ell], d), pcs.eq(point[source.ell:], d)
            basis = [tuple(int(i == a) for i in range(d)) for a in range(d)]
            pieces = []
            for piece in (0, 1):
                if (piece == 0 and not q) or (piece == 1 and not tail): continue
                a = [v if (u < q if piece == 0 else u == q) else zero for u, v in enumerate(rows_eq)]
                coef = [sc.mul(v, e) if piece == 0 or i < tail else zero for i, v in enumerate(suffix_eq) for e in basis]
                value = zero
                for i in range(real):
                    if piece == 0 or i % width < tail:
                        value = sc.add(value, sc.mul(mu[j][i], sc.mul(a[i//width], suffix_eq[i%width])))
                pieces.append((piece, a, coef, value))
            assert pcs.dot([one]*len(pieces), [p[3] for p in pieces], d) == rr['values'][0]
            claims = struct.pack('<QBB', identity, j, len(pieces))+pcs.field_bytes([*point, rr['values'][0]])
            for piece, _, _, value in pieces:
                claims += bytes([piece])+sc.encode(value)
                out += sc.encode(value)
            t.absorb(CLAIMS, claims)
            for piece, a, coef, value in pieces:
                out += pcs.open_functional(t, piece, mu_handles[j], prepared_mu[j], a, coef, value)
    except ValueError as error:
        assert checking_roots and str(error) in ('RootMismatch', 'Pole'), f'unexpected reference failure: {error}'
        result.update(outcome='error', cause=f'Fraction({error})')
    else:
        result.update(outcome='produced', proof=out.hex(), public_bytes=t.public_bytes-public_before+registration_bytes)
    usage['transcript'] = t.usage.copy()
    result['usage'] = usage
    if result['outcome'] == 'produced': result['continuation'] = t.challenge()[0].hex()
    return result

def cases():
    for degree in (4, 8):
        partial = [(0, 1), (1, 0), (2, 0)]
        random.Random(307252).shuffle(partial)
        for name, table, params, m, b, repeats, tuples, selector, layouts in (
            ('scalar', 'range_8', [], 0, 0, 1, [(7,)], [1], [(4, 1)]),
            ('partial', 'exp_q/hi', [7, 0, 0, 6], 2, 0, 2, partial+[(0, 0)], [1, 1, 1, 0], [(1, 1), (0, 2)]),
            ('signed', 'exp_q/direct', [7, 0, 0], 2, 2, 1, [(-128, 0), (-1, 0), (0, 1), (0, 0)], [1, 1, 1, 0], [(4, 1)]),
            ('late-failure', 'range_8', [], 0, 0, 2, [(256,)], [1], [(4, 1), (4, 1)]),
        ):
            yield dict(name=f'{name}-{degree}', degree=degree, public_hex=PUBLIC.hex(), lookup_id=7,
                m=m, b=b, table=dict(name=table, version=1, params_hex=bytes(params).hex()), selector=selector,
                originals=[dict(id=10+a, ell=0 if a == 0 else m, blowup=1, message=[row[a] % sc.P for row in tuples]) for a in range(len(tuples[0]))],
                multiplicities=[dict(id=20+j, ell=ell, blowup=blowup) for j, (ell, blowup) in enumerate(layouts)])

def main():
    inputs = list(cases())
    old = pcs.Transcript
    pcs.Transcript = Transcript
    try:
        expected = [reference(case) for case in inputs]
        from lookup_closed import batch
        closed_inputs, closed_expected = batch(sys.modules[__name__], inputs, expected)
    finally:
        pcs.Transcript = old
    assert len(expected) == 8 and sum(v['outcome'] == 'produced' for v in expected) == 6
    assert all(v['cause'] == 'Fraction(RootMismatch)' for v in expected if v['outcome'] == 'error')
    digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert digest == EXPECTED, f'independent lookup corpus digest: {digest}'
    closed_digest = hashlib.sha256(json.dumps(closed_expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert len(closed_expected) == 40 and sum(v['decision'] == 'accept' for v in closed_expected) == 8
    assert closed_digest == CLOSED_EXPECTED, f'independent closed lookup corpus digest: {closed_digest}'
    native = subprocess.run(['cargo', 'run', '-q', '-p', 'stele-negative-controls', '--example', 'lookup_corpus', '--locked', '--offline'],
        cwd=ROOT, input=''.join(json.dumps(case)+'\n' for case in inputs+closed_inputs), text=True, capture_output=True)
    assert native.returncode == 0, native.stderr
    actual = [json.loads(line) for line in native.stdout.splitlines()]
    assert len(actual) == len(expected)+len(closed_expected)
    for case, left, right in zip(inputs+closed_inputs, actual, expected+closed_expected):
        assert left == right, f'lookup mismatch {case["name"]}: {[k for k in left.keys() | right.keys() if left.get(k) != right.get(k)]}'
    print(f'lookup producer corpus: 8 complete cases; QM31/OM31; bytes, registration, usage, public payloads and continuation; SHA256 {digest}; no lookup verification credit')
    print(f'lookup closed corpus: 40 complete cases; QM31/OM31; 8 accepts and 32 rejects; actual records, imports, failure usage and continuation; SHA256 {closed_digest}')

if __name__ == '__main__':
    main()
