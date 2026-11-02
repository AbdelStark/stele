"""Data-only RFC-0023 producer evidence projection and positive-target control.

No proof engine is called. Historical results are supplied explicitly, hash-checked,
and projected without modifying or rerunning their original frozen campaign.
"""
import argparse
import hashlib
import json
from math import prod
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'tests/negative-controls'))
from requant_schema import MODULES, Schema

PINS = {
    '596c63ae4bf00f4de9b4a521d67a67c2340bec8e8bc2f3c8200170350b472adb',
    'e6203b873e0461c1889a4819f9ecd1aab6f175037c6c775201ecd40c1c15a202',
    '653a92864e7efe23d8790c3da539aaa7c8649866c9c98681f0506b5fbc5d8c2e',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def positive_target(bits):
    schema = Schema(1, 0, bits)
    h = 1 << (bits-1)
    values = dict(v=h, a=h, q=h, qd=h, r0=0, t=h, w0=(1 << 31)+h, u=h, z0=0)
    req, limbs = MODULES['requant'], MODULES['limbs']
    w = dict(magnitude=h, sign=0, product=h, quotient=h, scaled_quotient=h, remainder=0)
    pairs = req.column_inputs(schema.spec, h, w)
    for role, spec in req.column_specs(schema.spec).items():
        carries = limbs.witness(spec, *pairs[role])['carry']
        for k, block in enumerate(schema.role_carries[role], 1):
            values[block.name] = carries[k]
    advice = [0]*schema.R
    caps = list(schema.blocks.items())+[(schema.targets[role], b) for role, b in schema.result_caps.items()]
    for name, block in caps:
        value = values[name]
        assert 0 <= value <= block.cap
        for rows, number in [(block.rows, value), (block.slack, block.cap-value)]:
            for k, row in enumerate(rows): advice[row] = (number >> (8*k)) & 255
        carry = 0
        for k, row in enumerate(block.rows):
            carry = (advice[row]+advice[block.slack[k]]+carry)//256
            if k < len(block.carry): advice[block.carry[k]] = carry
        assert carry == 0
    row = [1]+list((h+(1 << 31)).to_bytes(4, 'little'))+advice
    residuals = [(name, sum(c*prod(row[f] for f in factors) for c, factors in terms))
                 for name, terms in schema.constraints()]
    assert [(name, value) for name, value in residuals if value] == [('target', 1)]
    return bytes(advice)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, action='append', required=True)
    args = parser.parse_args()
    observed, cases, sources = set(), {}, {}
    for path in args.result:
        raw = path.read_bytes(); digest = sha(raw)
        assert digest in PINS and digest not in observed
        observed.add(digest)
        data = json.loads(raw)
        for case in data['cases']:
            if case.get('decision') != 'accept':
                assert case['name'] in ('high-tail-K4','high-tail-K8')
                continue
            name = case['name']; assert name not in cases
            # Only the first honest producer precedes the first advice verifier import.
            prefix = []
            for observation in case['all_child_hash_observations']:
                if observation['scope'] == 'advice-import-verifier': break
                prefix.append(observation)
            lookups = [x['usage'] for x in case['producer_lookups']]
            assert len(lookups) == 2
            openings = [x for x in prefix if x['scope'].startswith('produce-A9-')]
            assert [x['scope'] for x in openings] == ['produce-A9-0','produce-A9-1','produce-A9-2']
            local = {k: sum(x['non_transcript'][k] for x in lookups+openings)
                     for k in lookups[0]['non_transcript']}
            # The native producer additionally checks its caller-owned advice packet.
            # This same primitive was observed in the old verifier, not old production.
            identity = next(x for x in case['all_child_hash_observations']
                            if x['scope'] == 'outer-advice-packet-identity')
            assert identity['outcome'] == 'success' and identity['created_transcripts'] == []
            assert identity['non_transcript'] == {k:int(k=='hash_evaluations') for k in local}
            local = {k:v+identity['non_transcript'][k] for k,v in local.items()}
            cases[name] = dict(source_sha256=digest, input_production=case['input_production'],
                advice_production=[x for x in prefix if x['scope'] in ('advice-commit','advice-certify','advice-import-prover')],
                usage=dict(transcript=case['prover_usage_before_continuation'], non_transcript=local,
                           registrations=[x['registrations'] for x in lookups]))
    assert observed == PINS and len(cases) == 10
    for p in [Path(__file__), ROOT/'tests/negative-controls/requant_schema.py', *[Path(m.__file__) for m in MODULES.values()]]:
        sources[str(p.relative_to(ROOT))] = sha(p.read_bytes())
    out = ROOT/'tests/negative-controls/fixtures/requant-production'
    out.mkdir(exist_ok=True)
    files = {'usage.json': (json.dumps(cases, sort_keys=True, separators=(',',':'))+'\n').encode()}
    files |= {f'positive-h-{bits}.bin':positive_target(bits) for bits in (8,16)}
    manifest = dict(qualification='Historical producer Usage projected without proof execution; two independent integer-only positive-H candidates, only target residual is +1.',
                    original_results=sorted(PINS),sources=sources,
                    files={name:dict(bytes=len(raw),sha256=sha(raw)) for name,raw in files.items()})
    files['manifest.json'] = (json.dumps(manifest,indent=2,sort_keys=True)+'\n').encode()
    for name, raw in files.items():
        path=out/name
        if path.exists(): assert path.read_bytes()==raw, name
        else: path.write_bytes(raw)
    print(f'{len(cases)} saved producer observations; 2 positive-H candidates; no proof execution')


if __name__ == '__main__': main()
