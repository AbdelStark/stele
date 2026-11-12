"""Tamper suite for a stored dev-zk proof (task E12-30): verify only, never prove.

  python3 bench/dev_zk_tamper.py RUN_DIR --stele target/release/stele --expect-model HEX [--json OUT]

RUN_DIR holds `public.bin` (`stele-dev-zk-public-v1`/`-v2`) and `proof.bin` (`stele-dev-zk-v1`).
Offsets come from decoding both files (the `bundle::encode_zk` and `zk::claims::encode`
layouts), never from fixed byte positions. Each case writes a mutated copy, runs
`verify-dev --expect-model`, and checks the exact rejection; the unchanged copy must
verify. A QM31 value is mutated by adding 1 to its first M31 limb (mod p), so it stays
canonical and the rejection is the verifier's check, not the decoder's.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

P = (1 << 31) - 1
K = 16  # QM31 bytes
PROOF_MAGIC = b'stele-dev-zk-v1'


class Reader:
    def __init__(self, data, at=0):
        self.data, self.at = data, at

    def take(self, n):
        start = self.at
        self.at += n
        assert self.at <= len(self.data), 'Truncated'
        return start

    def u32(self):
        start = self.take(4)
        return int.from_bytes(self.data[start:start + 4], 'little')

    def blob(self):
        n = self.u32()
        return self.take(n), n


def public_layout(data):
    """Offsets of the dev-zk public file's fields (bundle::encode_zk)."""
    for magic, byte in ((b'stele-dev-zk-public-v2', 4), (b'stele-dev-zk-public-v1', 1)):
        if data.startswith(magic):
            break
    else:
        raise ValueError('NotDevZk')
    r = Reader(data, len(magic))
    for _ in range(3):  # model, scales, preparation
        r.blob()
    for _ in range(r.u32()):  # 1-D records: ordinal, codes
        r.take(2)
        r.blob()
    for _ in range(r.u32()):  # commitment: root, certificate
        r.take(32)
        r.blob()
    count = r.u32()
    tokens = r.take(4 * count)
    start, end = r.take(4), r.take(4)
    has_next = data[r.take(1)]
    assert has_next == 1, 'NoNext'
    nxt = r.take(4)
    index = r.take(4)
    return dict(magic=(0, len(magic)), byte=byte, tokens=tokens, count=count, start=start, end=end,
                next=nxt, index=index)


def proof_layout(data):
    """Offsets of the dev-zk proof's sections (zk::claims::encode after the header)."""
    assert data.startswith(PROOF_MAGIC), 'NotDevZkProof'
    r = Reader(data, len(PROOF_MAGIC) + 64)
    out = {'sources': [], 'certificates': [], 'relations': [], 'gkr': [], 'batches': []}
    for name in ('sources', 'certificates'):
        for _ in range(r.u32()):
            out[name].append(r.blob())

    def sumcheck():
        s = {'mask_sum': r.take(K), 'rounds': []}
        for _ in range(r.u32()):
            n = r.u32()
            s['rounds'].append((r.take(K * n), n))
        n = r.u32()
        s['finals'] = (r.take(K * n), n)
        s['mask_final'] = r.take(K)
        return s

    for name in ('relations', 'gkr'):
        for _ in range(r.u32()):
            out[name].append(sumcheck())
    for _ in range(r.u32()):
        out['batches'].append({'sumcheck': sumcheck(), 'opening': r.blob()})
    out['shared'] = {'source': r.blob(), 'certificate': r.blob(), 'sumcheck': sumcheck(), 'opening': r.blob()}
    out['shared_opening'] = r.blob()
    assert r.at == len(data), 'TrailingBytes'
    return out


def bump_qm31(data, at):
    """Add 1 to the first M31 limb of the QM31 value at `at`, keeping it canonical."""
    limb = int.from_bytes(data[at:at + 4], 'little')
    data[at:at + 4] = ((limb + 1) % P).to_bytes(4, 'little')


def flip(data, at):
    data[at] ^= 1


def cases(public, proof):
    pub, prf = public_layout(public), proof_layout(proof)
    witness_cert, _ = prf['certificates'][0]
    batch_open, _ = prf['batches'][0]['opening']
    relation = prf['relations'][len(prf['relations']) // 2]
    gkr = prf['gkr'][len(prf['gkr']) // 2]
    finals, _ = prf['relations'][0]['finals']
    shared_open, n_shared = prf['shared_opening']
    source0, n_source0 = prf['sources'][0]
    return [
        # name, file, mutation(bytearray), expected last line of verify-dev
        ('unchanged', 'proof', lambda d: None, 'YES'),
        # RFC-0010 A14 item 4: a byte-4 certificate starts `u8(1) || n_t || t_bytes` when k_t >= 1.
        ('grinding nonce (witness certificate n_t)', 'proof', lambda d: flip(d, witness_cert + 1),
         'NO: Zk(Pcs(Transcript(GrindMismatch)))'),
        # A changed root changes the certificate transcript, so the stored nonce fails first.
        ('source bytes (witness, last byte: its root)', 'proof', lambda d: flip(d, source0 + n_source0 - 1),
         'NO: Zk(Pcs(Transcript(GrindMismatch)))'),
        ('certificate (witness, last byte)', 'proof',
         lambda d: flip(d, witness_cert + prf['certificates'][0][1] - 1), 'NO: Zk(Pcs(Merkle(RootMismatch)))'),
        ('masked sumcheck round (a relation)', 'proof', lambda d: bump_qm31(d, relation['rounds'][0][0]),
         'NO: Zk(Sumcheck(RoundSumMismatch))'),
        ('ZK-GKR round (a step)', 'proof', lambda d: bump_qm31(d, gkr['rounds'][0][0]),
         'NO: Zk(Sumcheck(RoundSumMismatch))'),
        ('claim (a relation final value)', 'proof', lambda d: bump_qm31(d, finals),
         'NO: Zk(Sumcheck(FinalEvaluationMismatch))'),
        # Mid-opening: the absorbed row changes, so the column nonce fails; last byte: a
        # column response, so its Merkle path fails.
        ('opening row (witness batch, middle byte)', 'proof',
         lambda d: flip(d, batch_open + prf['batches'][0]['opening'][1] // 2), 'NO: Zk(Pcs(Transcript(GrindMismatch)))'),
        ('opening response (witness batch, last byte)', 'proof',
         lambda d: flip(d, batch_open + prf['batches'][0]['opening'][1] - 1),
         'NO: Zk(Pcs(Merkle(RootMismatch)))'),
        ('opening row (shared source, middle byte)', 'proof', lambda d: flip(d, shared_open + n_shared // 2), 'NO: Zk(Pcs(Transcript(GrindMismatch)))'),
        ('opening response (shared source, last byte)', 'proof', lambda d: flip(d, shared_open + n_shared - 1),
         'NO: Zk(Pcs(Merkle(RootMismatch)))'),
        ('public token', 'public', lambda d: d.__setitem__(slice(pub['tokens'] + 4, pub['tokens'] + 8),
                                                           (int.from_bytes(d[pub['tokens'] + 4:pub['tokens'] + 8], 'little') ^ 1).to_bytes(4, 'little')),
         'NO: StatementMismatch'),
        ('y', 'public', lambda d: d.__setitem__(slice(pub['next'], pub['next'] + 4),
                                                (int.from_bytes(d[pub['next']:pub['next'] + 4], 'little') ^ 1).to_bytes(4, 'little')),
         'NO: StatementMismatch'),
        ('window start r', 'public', lambda d: d.__setitem__(slice(pub['start'], pub['start'] + 4),
                                                             (int.from_bytes(d[pub['start']:pub['start'] + 4], 'little') - 1).to_bytes(4, 'little')),
         'NO: StatementMismatch'),
        ('proof index', 'public', lambda d: d.__setitem__(slice(pub['index'], pub['index'] + 4),
                                                          (int.from_bytes(d[pub['index']:pub['index'] + 4], 'little') ^ 1).to_bytes(4, 'little')),
         'NO: StatementMismatch'),
        ('profile byte (v2 file read as v1)', 'public',
         lambda d: d.__setitem__(slice(0, len(b'stele-dev-zk-public-v2')), b'stele-dev-zk-public-v1'),
         'NO: StatementMismatch'),
    ]


def run(stele, public, proof, model):
    out = subprocess.run([stele, 'verify-dev', '--public', str(public), '--proof', str(proof),
                          '--expect-model', model], capture_output=True, text=True)
    lines = (out.stdout + out.stderr).strip().splitlines()
    return lines[-1] if lines else ''


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('run', type=Path)
    p.add_argument('--stele', required=True)
    p.add_argument('--expect-model', required=True)
    p.add_argument('--json', type=Path)
    a = p.parse_args()
    public, proof = (a.run / 'public.bin').read_bytes(), (a.run / 'proof.bin').read_bytes()
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name, which, mutate, expected in cases(public, proof):
            data = bytearray(proof if which == 'proof' else public)
            mutate(data)
            pub_path, prf_path = tmp / 'public.bin', tmp / 'proof.bin'
            pub_path.write_bytes(data if which == 'public' else public)
            prf_path.write_bytes(data if which == 'proof' else proof)
            changed = bytes(data) != (proof if which == 'proof' else public)
            assert changed or name == 'unchanged', name
            got = run(a.stele, pub_path, prf_path, a.expect_model)
            ok = got == expected
            results.append(dict(case=name, file=which, expected=expected, got=got, ok=ok))
            print(f"{'ok ' if ok else 'BAD'} {name}: {got}", flush=True)
    if a.json:
        a.json.write_text(json.dumps(results, indent=1) + '\n')
    assert all(r['ok'] for r in results), 'TamperNotRejected'


if __name__ == '__main__':
    main()
