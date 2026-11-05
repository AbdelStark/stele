"""Manual E5-04 full original-Artifact Rust/NumPy qualification, no proof/fidelity claim.

Python3.12, numpy==1.26.4, blake3==1.0.11, python-flint==0.9.0,
safetensors==0.6.2. Reuses completed immutable E5-03c preparation; never reruns it.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from struct import pack
import subprocess
import sys

from blake3 import blake3
from numpy_execution import ROOT, Oracle, full_bytes, load
import artifact_codec
import model_codec
import request_bounds


def digest(path):
    h = sha256()
    with path.open('rb') as stream:
        while raw := stream.read(1 << 20):
            h.update(raw)
    return h.hexdigest()


def decision_bytes(position, token, values):
    arguments, weights, order, cdf, draw = values
    raw = pack('<II', position, token)
    for sequence, kind in ((arguments, 'i'), (weights, 'I'), (order, 'I'), (cdf, 'Q')):
        raw += pack('<I', len(sequence))+pack('<'+kind*len(sequence), *sequence)
    return raw+bytes((draw is not None,))+(b'' if draw is None else pack('<I', draw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prepared', 'receipt', 'native', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    native = args.native.resolve(strict=True)
    directory = args.prepared.resolve(strict=True)
    receipt_path = args.receipt.resolve(strict=True)
    assert receipt_path.is_relative_to(ROOT/'agents/reviews/e503c-original-preparation')
    preparation = json.loads(receipt_path.read_text())
    assert preparation['status'] == 'passed'
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    assert subprocess.run(['git', 'diff', '--quiet'], cwd=ROOT).returncode == 0, 'UncommittedSource'
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    paths = sorted((ROOT/'crates/stele-cqis/src').rglob('*.rs'))+sorted((ROOT/'crates/stele-field/src').rglob('*.rs'))
    paths += [ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'crates/stele-cqis/Cargo.toml',
              ROOT/'crates/stele-field/Cargo.toml', ROOT/'crates/stele-cqis/examples/execute_model.rs',
              Path(__file__).resolve(), ROOT/'crates/stele-cqis/tests/support/numpy_execution.py']
    paths += [Path(module.__file__).resolve() for module in tuple(sys.modules.values())
              if getattr(module, '__file__', None) and Path(module.__file__).resolve().is_relative_to(ROOT/'research')]
    pins = {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}
    for name in ('model.bin', 'preparation.bin', 'scales.bin', 'artifact.bin'):
        assert digest(directory/name) == preparation['artifacts'][name], ('FrozenInput', name)
    model = model_codec.decode((directory/'model.bin').read_bytes())
    mapping = artifact_codec.decode_preparation(model, (directory/'preparation.bin').read_bytes())
    scales_raw = (directory/'scales.bin').read_bytes()
    expected_id = bytes.fromhex(preparation['native_result']['digest_cqis'])
    raw = (directory/'artifact.bin').read_bytes()
    data = load(model, mapping, scales_raw, raw, expected_id)
    oracle = Oracle(data)
    family = model.shape.family
    sequence = (128000, 9906, 11) if family else (50256, 15496, 11)
    prompt = sequence[:2]
    seed = bytes(range(32)) if model.decoding is not None else None
    eos = (128001, 128008, 128009) if family else (50256,)
    boundary = request_bounds.Request(len(prompt), 2, eos, None if seed is None else blake3(b'stele/v0.1/cqis/sample-seed'+seed).digest())
    spec = request_bounds.Spec(model.shape.vocabulary, model.shape.context, int(seed is not None))
    request = request_bounds.encode_request(spec, boundary)
    inputs = dict(tokens=sequence, prompt=prompt, request=request.hex(), seed=None if seed is None else seed.hex())
    (output/'input.json').write_text(json.dumps(inputs, indent=2)+'\n')
    provenance = dict(repository=preparation['repository'], revision=preparation['revision'],
                      preparation_receipt_sha256=digest(receipt_path), preparation_inputs={name:preparation['artifacts'][name] for name in ('model.bin','preparation.bin','scales.bin','artifact.bin')},
                      head=head, source_pins=pins, native_sha256=digest(native),
                      numerical_identity=preparation['native_result']['cqis_id'], digest_cqis=expected_id.hex(),
                      selected_scalars=preparation['selected_scalars'], weight_bits=model.formats[0][0],
                      shape=model.shape.__dict__, input_sha256=digest(output/'input.json'))
    (output/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
    print(json.dumps(dict(phase='qualified_inputs', model=preparation['repository'], weight_bits=model.formats[0][0])), flush=True)
    with (output/'native.stdout').open('xb') as out, (output/'native.stderr').open('xb') as err:
        process = subprocess.Popen([str(native), str(directory), expected_id.hex(), str(output/'input.json'), str(output/'native.bin')], stdout=out, stderr=err)
        try:
            original = oracle.full(sequence)
            reference = bytearray(b'stele-e504-numerical-v1'+pack('<I', len(sequence))+full_bytes(sequence, original))
            del original
            print(json.dumps(dict(phase='numpy_original_full_complete')), flush=True)
            generated = prompt
            result = oracle.full(generated)
            decisions = []
            reason = 0
            for _ in range(boundary.maximum_new):
                token, decision = oracle.choose(result[1][-1], seed, len(generated))
                decisions.append(decision_bytes(len(generated), token, decision))
                generated += (token,)
                result = oracle.full(generated)
                if token in eos:
                    reason = 1
                    break
            request_bounds.check_completion(spec, boundary, prompt, generated, reason)
            reference.extend(bytes((reason,))+pack('<I', len(decisions))+b''.join(decisions))
            reference.extend(pack('<I', len(generated))+full_bytes(generated, result))
            del result
            assert process.wait() == 0, 'NativeFailure'
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()
    actual = (output/'native.bin').read_bytes()
    assert actual == reference, 'CompleteNativeNumpyParity'
    assert all(digest(ROOT/p) == h for p,h in pins.items()), 'SourceChangedDuringQualification'
    report = dict(provenance, status='passed', full_positions=len(sequence),
                  generated_positions=len(generated), decisions=len(decisions), stop_reason=reason,
                  compared_bytes=len(actual), output_sha256=sha256(actual).hexdigest(),
                  output_blake3=blake3(actual).hexdigest(), all_residual_logits_and_cache_bytes_equal=True,
                  native_full_cache_each_position_equal=True, native_generation_full_cache_equal=True,
                  boundary='Original numerical inference and decoding only; no fidelity, proof, privacy or profile admission.')
    (output/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    for path in output.iterdir():
        path.chmod(0o444)
    output.chmod(0o555)
    print(json.dumps(dict(status='passed', compared_bytes=len(actual), result_sha256=digest(output/'results.json'))), flush=True)


if __name__ == '__main__':
    main()
