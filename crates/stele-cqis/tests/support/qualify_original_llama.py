"""Manual complete original Llama-3.1-8B preparation; no benchmark/proof credit.

Python3.12, numpy==1.26.4, blake3==1.0.11, python-flint==0.9.0,
safetensors==0.6.2. Reuse only the frozen, fully qualified identical RoPE
reference digest; the native adapter still regenerates every coefficient.
"""
import argparse
from dataclasses import replace
from decimal import Decimal
from fractions import Fraction as Q
import json
from pathlib import Path
from random import Random
from struct import pack, unpack
import subprocess

import numpy as np
from blake3 import blake3
import qualify_original_gpt2 as base
import check_registry_codec as registry_oracle
import model_codec
import registry_codec
from model_codec import Model, Block, Rotation, Sampled
from rms_bounds import RMSNorm

ROOT = base.ROOT
REVISION = 'd04e592bb4f6aa9cfee91e2e20afa771667e1d4b'
PINS = {
    'config.json': '54acfad3cffe057640904ca8a1e83525e6551c70c7a04c641f5a9eda0bbf64bd',
    'generation_config.json': 'e645194d2dd27c86ed34a5a23f306c1a0fd79a42123c26551b7251c700a3379d',
    'model.safetensors.index.json': '146776fce3f6db1103aa6f249e65ee5544c5923ce6f971b092eee79aa6e5d37b',
    'special_tokens_map.json': '462d91939dbc37178aa5a3eae7068d1990ccc92e09f288cc71f42cdf139d69cc',
    'tokenizer_config.json': '8004530facf809ac432114de2a4dcc65fcb632da5ec16d666091aeb6a2ee444a',
    'tokenizer.json': '76e48799b099d43365bd24ccd8ecc5aedac831718da780552f03b0a6eb4412aa',
    'model-00001-of-00004.safetensors': 'f8b9704ab09cdeb097aa4a0a24bca96f906eec36bad63ab495bc21475058601b',
    'model-00002-of-00004.safetensors': 'c28b25e7541751056ee126627e007f8d4288319733285e9f7b17b9ff6eb313f0',
    'model-00003-of-00004.safetensors': 'd8e9504dd4e4a146d484c52a97584ec14dac92237c46b064934af67a85e7d383',
    'model-00004-of-00004.safetensors': 'e4486f35c040f683f7d790354f66c169c109eb9fa0954a4a35d7c458a108405d',
}
ROTATION_RECEIPT = 'ba79c35caccee80272ea99b7c7d8f224ace2d317884cabf9a352cfc2b215fb42'


def configuration(weight_bits=8):
    assert weight_bits in (4, 8)
    s = base.Shape(1, 32, 4096, 32, 8, 128, 14336, 128256, 131072)
    norm = RMSNorm(4096, 7, 8, 7, 1, 100000)
    rotation = Rotation(128, s.context, 2, 1, 8192,
                        ((500000, 1), (8, 1), (1, 1), (4, 1)))
    b = Block(norm, norm, (7,)*7, 7, 7, 7, ((0, 0),)*7, 46341, -19, 0, 0,
              base.Exponential(s.context, 15, 7, 14, 0),
              base.Activation(s.hidden, 1, 7, 7), rotation)
    formats = tuple((weight_bits, 0) if len(ds) == 2 else (16, 8)
                    for _, _, ds in base.roles(s))
    sampled = Sampled(3, 5, 9, 10, base.Exponential(s.vocabulary, 15, 7, 14, 0))
    model = Model(s, formats, 7, (b,)*s.layers, norm, (0, 0), 7, sampled)
    mapping = base.mapped(model, 2, Random(50560))
    mapping = replace(mapping, entries=tuple(replace(e, dtype=2) for e in mapping.entries),
                      aliases=(), ignored=())
    return model, mapping


def frozen_rotation(directory, expected):
    """Recover one exact-definition digest from the full prior independent run."""
    assert base.digest(directory/'results.json') == ROTATION_RECEIPT, 'RotationReceipt'
    receipt = json.loads((directory/'results.json').read_text())
    assert receipt['status'] == 'passed' and receipt['rotation_pairs'] == 8388608
    for name in ('model.bin', 'native.bin', 'reference.bin'):
        assert base.digest(directory/name) == receipt['artifacts'][name], ('RotationArtifact', name)
    for name, digest in receipt['sources'].items():
        if name.startswith('research/') and name.endswith('.py'):
            assert base.digest(ROOT/name) == digest, ('RotationOracleChanged', name)
    old = model_codec.decode((directory/'model.bin').read_bytes())
    raw = (directory/'reference.bin').read_bytes()
    native = (directory/'native.bin').read_bytes()
    assert native == pack('<I', len(raw))+raw
    position, found = 0, []
    for part in registry_codec._parts(old):
        if type(part) is bytes:
            assert raw[position:position+len(part)] == part
            position += len(part)
        else:
            data = raw[position:position+32]
            assert len(data) == 32
            if type(part) is Rotation:
                assert part == expected, 'RotationDefinition'
                found.append((part.encode(), data))
            position += 32
    assert position == len(raw) and len(found) == 1
    return found[0]


def registry_frame(model, qualified_rotation=None):
    """Independent complete framing and fresh function data; exact RoPE evidence."""
    functions, tables, rotations, refs = {}, {}, {}, []
    roles = [v for b in model.blocks for v in (b.norm1, b.exp, b.norm2, b.activation)]
    roles.append(model.final_norm)
    if model.decoding is not None:
        roles.append(model.decoding.exp)
    for value in roles:
        f, r = registry_oracle.split_selection(value)
        fid = blake3(f).digest()
        functions[fid] = (f, r)
        refs.append(fid+blake3(r).digest())
        for spec in registry_oracle.components(value):
            raw = registry_oracle.descriptor(b'stele/v0.1/table/identity', *spec)
            tables[blake3(raw).digest()] = (raw, spec)
    parts = [b'stele/v0.1/cqis/functions', pack('<I', len(functions))]
    for _, (f, r) in sorted(functions.items()):
        parts.extend((pack('<H', len(f)), f, pack('<H', len(r)), r))
    parts.append(pack('<I', len(tables)))
    for _, (raw, spec) in sorted(tables.items()):
        parts.extend((pack('<H', len(raw)), raw, registry_oracle.table_digest(spec)))
    manifest = b''.join(parts)
    parts = [b'stele/v0.1/cqis/registry', blake3(base.model_frame(model)).digest(),
             pack('<H', len(roles)), b''.join(refs), pack('<I', len(manifest)), manifest,
             pack('<H', len(model.blocks))]
    for block in model.blocks:
        value = block.rotation
        if value is None:
            parts.append(b'\0')
        else:
            rid = blake3(registry_oracle.rotation(value)).digest()
            rotations[rid] = value
            parts.append(b'\1'+rid)
    parts.append(pack('<H', len(rotations)))
    for _, value in sorted(rotations.items()):
        raw = registry_oracle.rotation(value)
        if qualified_rotation is None:
            data = registry_oracle.rotation_digest(value)
        else:
            assert raw == qualified_rotation[0], 'RotationDefinition'
            data = qualified_rotation[1]
        parts.extend((pack('<I', len(raw)), raw, data))
    return b''.join(parts)


def check_bf16():
    for word in range(65536):
        e = (word >> 7) & 255
        if e == 255:
            continue
        n = (word & 127)+(128 if e else 0)
        value = (-1 if word >> 15 else 1)*Q(n)*Q(2)**(e-134 if e else -133)
        assert base.exact(word << 16) == value
    base.check_rounding()
    base.check_packing()


def verify_artifact(model, mapping, source_dir, artifact_path):
    index = json.loads((source_dir/'model.safetensors.index.json').read_text())
    headers, sources = {}, {}
    for name in sorted(set(index['weight_map'].values())):
        with (source_dir/name).open('rb') as stream:
            length = unpack('<Q', stream.read(8))[0]
            header = json.loads(stream.read(length))
        header.pop('__metadata__', None)
        sources[name] = np.memmap(source_dir/name, mode='r', dtype=np.uint8)
        for key, value in header.items():
            assert key not in headers and index['weight_map'][key] == name
            headers[key] = (name, length, value)
    assert set(headers) == set(index['weight_map']) == {e.name for e in mapping.entries}
    assert sum(v['data_offsets'][1]-v['data_offsets'][0] for _, _, v in headers.values()) == index['metadata']['total_size']
    scales, count, digest = [], 0, blake3()
    with artifact_path.open('rb') as actual:
        def emit(raw):
            assert actual.read(len(raw)) == raw, ('ArtifactMismatch', actual.tell())
            digest.update(raw)
        emit(b'cqis-weights-v1'+blake3(base.preparation(model, mapping)).digest()+pack('<H', len(mapping.entries)))
        for ordinal, (entry, (_, _, dims), (bits, fraction), ci) in enumerate(zip(
                mapping.entries, base.roles(model.shape), model.formats, base.configurations(model))):
            name, length, d = headers[entry.name]
            assert d['dtype'] == 'BF16' and tuple(d['shape']) == entry.shape == dims
            assert entry.transform == 0 and entry.part is None
            values = np.ndarray(dims, dtype='<u2', buffer=sources[name], offset=8+length+d['data_offsets'][0])
            parts = [b'stele/v0.1/cqis/tensor', pack('<I', len(ci)), ci]
            if len(dims) == 2:
                q, peaks = (1 << (bits-1))-1, []
                for start in range(0, dims[0], 128):
                    words = values[start:start+128]
                    assert not np.any(((words >> 7) & 255) == 255), 'Nonfinite'
                    peaks.extend(np.max(words & 0x7fff, axis=1).tolist())
                maximum, e = base.exact(max(peaks) << 16), 0
                if maximum:
                    e = maximum.numerator.bit_length()-maximum.denominator.bit_length()-(q*65535).bit_length()+1
                    while maximum > q*65535*Q(2)**e:
                        e += 1
                    while maximum <= q*65535*Q(2)**(e-1):
                        e -= 1
                ms = []
                for peak in peaks:
                    ratio = base.exact(peak << 16)/(q*Q(2)**e)
                    ms.append(max(1, -(-ratio.numerator//ratio.denominator)))
                assert all(1 <= m <= 65535 for m in ms)
                scale = base.Scale(e, pack('<'+'H'*len(ms), *ms))
                scales.append(scale)
                parts.extend((pack('<h', e), scale.mantissas))
            size = (int(values.size)*bits+7)//8
            metadata = b''.join(parts+[pack('<Q', size)])
            emit(pack('<Q', len(metadata)+size)+metadata)
            for start in range(0, dims[0], 128):
                words = values[start:start+128].astype(np.uint32) << 16
                if len(dims) == 2:
                    m = np.array(ms[start:start+128], dtype=np.uint64)[:, None]
                    codes = base.rounded(words, m, e, -q, q)
                    assert start+len(words) == dims[0] or words.size % 2 == 0
                    payload = base.packed(codes, bits)
                else:
                    payload = base.rounded(words, 1, -fraction, -32768, 32767).astype('<i2').tobytes(order='C')
                emit(payload)
                count += int(words.size)
            print(json.dumps({'verified_physical_record': ordinal, 'scalars': count}), flush=True)
        assert actual.read(1) == b'', 'ArtifactSuffix'
    return tuple(scales), digest.hexdigest(), count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-dir', 'native', 'output-dir', 'rotation-reference'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--weight-bits', type=int, choices=(4, 8), required=True)
    args = parser.parse_args()
    source_dir, native = args.source_dir.resolve(strict=True), args.native.resolve(strict=True)
    root = args.output_dir.resolve()
    root.mkdir(exist_ok=False)
    inputs = root/'inputs'
    inputs.mkdir()
    checked = {}
    for name, expected in PINS.items():
        assert base.digest(source_dir/name) == expected, ('OriginalFile', name)
        checked[name] = base.sc.File(name, (source_dir/name).stat().st_size, bytes.fromhex(expected))
    generation = json.loads((source_dir/'generation_config.json').read_text(), parse_float=Decimal)
    assert generation['do_sample'] is True and Q(generation['temperature']) == Q(3, 5) and Q(generation['top_p']) == Q(9, 10)
    model, mapping = configuration(args.weight_bits)
    mr = base.model_frame(model)
    assert mr == model_codec.encode(model)
    source = base.sc.Source(1, checked['model.safetensors.index.json'],
                            tuple(checked[n] for n in sorted(PINS) if n.endswith('.safetensors')))
    assets = base.sc.Assets(checked['config.json'], tuple(checked[n] for n in
        ('special_tokens_map.json', 'tokenizer.json', 'tokenizer_config.json')), checked['generation_config.json'])
    rotation = frozen_rotation(args.rotation_reference.resolve(strict=True), model.blocks[0].rotation)
    frames = {'model.bin': mr, 'preparation.bin': base.preparation(model, mapping),
              'source.bin': base.sc.encode_source(source), 'assets.bin': base.sc.encode_assets(assets)}
    for name, raw in frames.items():
        (inputs/name).write_bytes(raw)
    sources = sorted((ROOT/'crates/stele-cqis/src').rglob('*.rs'))
    sources += [ROOT/'crates/stele-cqis/examples/prepare_source.rs', Path(__file__).resolve(), Path(base.__file__), ROOT/'Cargo.lock']
    pins = {str(p.relative_to(ROOT)): base.digest(p) for p in sources}
    receipt = dict(repository='meta-llama/Llama-3.1-8B', revision=REVISION, original_files=PINS,
        source_pins=pins, native_sha256=base.digest(native), weight_bits=args.weight_bits,
        head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        rotation_reference_receipt_sha256=ROTATION_RECEIPT,
        parameters='Explicit int4/int8 matrices; vectors G=8; residual/projection/norm/activation F=7; dynamic row scales; score 46341*2^-19; exact accumulation; direct exp bits=15,F=7,E=14; original temperature3/5,top_p9/10; original full RoPE. No calibration/fidelity claim.')
    (root/'inputs.json').write_text(json.dumps(receipt, indent=2)+'\n')
    with (root/'native.stdout').open('xb') as out, (root/'native.stderr').open('xb') as err:
        print('starting native complete original preparation', flush=True)
        subprocess.run([str(native), *(str(inputs/n) for n in frames), '2', str(source_dir), str(root/'native')],
                       stdout=out, stderr=err, check=True)
    result = root/'native'
    check_bf16()
    scales, artifact_id, count = verify_artifact(model, mapping, source_dir, result/'artifact.bin')
    sr = base.scales_frame(model, scales)
    assert (result/'scales.bin').read_bytes() == sr
    auxiliary = {n: (source_dir/n).read_bytes() for n in PINS if not n.endswith('.safetensors') and n != 'model.safetensors.index.json'}
    assert (result/'source-config.bin').read_bytes() == base.source_architecture.binding(model, mapping, 2, assets, auxiliary)
    rr = registry_frame(model, rotation)
    assert (result/'registry.bin').read_bytes() == rr
    records, bound_hash = base.expected_records(model, scales), blake3()
    with (result/'bounds.bin').open('rb') as actual:
        def compare(raw):
            assert actual.read(len(raw)) == raw
            bound_hash.update(raw)
        compare(b'stele/v0.1/cqis/bounds'+b''.join(blake3(raw).digest() for raw in (mr, sr, rr))+pack('<H', len(records)))
        for ordinal, (_, _, parameters) in enumerate(records):
            raw = base.record_oracle(parameters)
            compare(pack('<HI', ordinal, len(raw))+raw)
        assert actual.read(1) == b''
    identity = b'stele/v0.1/cqis/identity'+b''.join(blake3(raw).digest() for raw in (mr, sr, rr))+bound_hash.digest()
    assert (result/'identity.bin').read_bytes() == identity
    reported = json.loads((result/'result.json').read_text())
    assert reported['digest_cqis'] == artifact_id and reported['cqis_id'] == blake3(identity).hexdigest()
    assert count == 8030261248 and all(base.digest(ROOT/n) == h for n, h in pins.items())
    receipt.update(status='passed', native_result=reported, selected_scalars=count,
        bf16_finite_encodings=65280, rounding_reference_cases=10000,
        artifacts={p.name: base.digest(p) for p in sorted(result.iterdir())},
        boundary='Complete original source numerical preparation; every Artifact/Scales/Registry/Bounds byte compared. No inference, fidelity, proof, passport, privacy or profile completion.')
    (root/'results.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({'status': 'passed', 'selected_scalars': count, 'digest_cqis': artifact_id,
                      'cqis_id': reported['cqis_id']}), flush=True)


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('reference assertions must remain enabled')
    main()
