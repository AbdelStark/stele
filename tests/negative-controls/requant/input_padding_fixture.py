# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Construct only the two missing input-padding controls from frozen A5 packets.

The original input/advice authority and complete expected statement stay fixed.
Only the producer arithmetic view U[0][3] changes. Existing actual reference A3
production emits the replacement packet; its original suffix is unreachable.
This never invokes the frozen run.py campaign or produces another A5 proof.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT/'tests/negative-controls/fixtures/requant'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def construct(ref, Schema, Protocol, Reader, statement, degree):
    baseline_name = f'padded-K{degree}'
    raw_case = (FIXTURES/(baseline_name+'.json')).read_bytes()
    case = json.loads(raw_case)
    wire = (FIXTURES/case['wire']).read_bytes()
    manifest = json.loads((FIXTURES/'manifest.json').read_text())
    assert sha(wire) == manifest['files'][case['wire']]['sha256']
    assert sha(raw_case) == next(c['sha256'] for c in manifest['cases'] if c['file'] == baseline_name+'.json')
    s = Schema(ref, 1, 2, 8, 3, stage=31)
    ref.degree = degree
    input_source = ref.pcs.Source(degree, 73, 2, 2, 1, bytes.fromhex(case['input_source'])[73:])
    certificate = (FIXTURES/case['input_certificate']).read_bytes()
    assert input_source.bytes().hex() == case['input_source']
    p = Protocol(ref, s, degree, 1, dict(source=input_source, certificate=certificate),
                 [tuple(x) for x in case['point']], tuple(case['value']),
                 bytes.fromhex(case['public_hex']), 1)
    p.preflight(wire)
    reader = Reader(wire)
    assert reader.take(2) == bytes([1, degree])
    advice_source = ref.pcs.Source(degree, s.S+2, s.a0, s.m, 1, reader.take(32))
    advice = ref.pcs.verify_certificate(advice_source, reader.take(p.adapter.size(advice_source, 0)))
    p.preflight_children(wire, advice)
    t = ref.Transcript(p.public, degree)
    t.absorb(statement, p.statement(advice))
    # Genuine immutable saved A5 packets, consumed by the real reference verifier.
    for group, handle in enumerate((p.input, advice)):
        lookup_case, geometry = p.geometry(group, handle)
        lookup_case['proof'] = reader.take(p.adapter.proof_size(lookup_case, geometry)).hex()
        receipt = p.adapter.verify(lookup_case, geometry, t)
        assert receipt['decision'] == 'accept'
        assert receipt['usage'] == case['expected']['records']['lookups'][group]['usage']
    aggregate = p.aggregate(t)
    inputs, advice_matrix = s.witness([-1, 0, 1])
    tables = [[ref.sc.scalar(int(i < s.n), degree) for i in range(s.N)]]
    tables += [[ref.sc.scalar(v, degree) for v in row] for row in inputs+advice_matrix]
    assert tables[1][3] == ref.sc.scalar(0, degree)
    tables[1][3] = ref.sc.scalar(1, degree)  # Exactly one arithmetic-view input byte.
    # Diagnose the isolated violated binding; this is not acceptance evidence.
    scalar_values = [int(i == 1) for i in range(len(tables))]
    residuals = []
    for name, terms in s.constraints:
        total = 0
        for coefficient, factors in terms:
            term = coefficient
            for factor in factors:
                term *= scalar_values[factor]
            total += term
        if total:
            residuals.append((name, total))
    assert residuals == [('input.padding[0]', 1)]
    proof = ref.zc.prove(t, aggregate, tables)
    packet = p.arithmetic_bytes(proof, zero=True)
    size = 4*degree*(4*s.m+5+s.R)
    assert len(packet) == size
    start = reader.at
    candidate = wire[:start]+packet+wire[start+size:]
    assert candidate[:start] == wire[:start] and candidate[start+size:] == wire[start+size:]
    try:
        p.verify(candidate)
    except ValueError as error:
        assert str(error) == 'RoundSumMismatch'
        state = p.last_verification
        assert state['phase'] == 'aggregate-A3'
        lookups = state['records']['lookups']
        assert len(lookups) == 2
        expected = dict(decision='RoundSumMismatch', phase='aggregate-A3',
                        failed_prefix_usage=state['transcript'].usage.copy(),
                        local_hashes=1+sum(l['usage']['non_transcript']['hash_evaluations'] for l in lookups),
                        registrations=[l['registrations'] for l in lookups])
    else:
        raise AssertionError('false input-padding candidate accepted')
    name = f'input-padding-K{degree}'
    result = dict(qualification='One changed arithmetic-view byte; original statement, sources, A5 packets and unreachable suffix unchanged.',
                  baseline=baseline_name, baseline_sha256=sha(wire), case_sha256=sha(raw_case),
                  changed_table=1, changed_position=3, before=0, after=1,
                  arithmetic_offset=start, arithmetic_size=size, residuals=residuals,
                  wire=name+'.bin', wire_sha256=sha(candidate), wire_bytes=len(candidate), expected=expected)
    for filename, content in [(name+'.bin', candidate), (name+'.json', (json.dumps(result, indent=2, sort_keys=True)+'\n').encode())]:
        output = FIXTURES/filename
        assert not output.exists(), 'never replace an executed fixture'
        output.write_bytes(content)
    print(f'{name}: reference RoundSumMismatch; original source authority preserved; SHA256 {sha(candidate)}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', required=True, type=Path)
    args = parser.parse_args()
    helper = args.helper.resolve()
    pins = json.loads((helper/'source-pins.json').read_text())
    for path, digest in pins.items():
        assert sha((ROOT/path).read_bytes()) == digest, path
    helper_pins = json.loads((FIXTURES/'manifest.json').read_text())['helper_source_pins']
    for name, digest in helper_pins.items():
        assert sha((helper/name).read_bytes()) == digest, name
    sys.path.insert(0, str(helper))
    refs = importlib.import_module('references')
    Schema = importlib.import_module('schema').Schema
    protocol = importlib.import_module('protocol')
    with refs.load(ROOT) as ref:
        for degree in (4, 8):
            construct(ref, Schema, protocol.Protocol, protocol.Reader, refs.STATEMENT, degree)
    provenance = dict(script_sha256=sha(Path(__file__).read_bytes()), sources=pins, helper_sources=helper_pins,
                      qualification='Exactly two new controls; saved A5 verification plus actual small A3 production; no original campaign rerun.')
    target = FIXTURES/'input-padding-provenance.json'
    assert not target.exists()
    target.write_text(json.dumps(provenance, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    main()
