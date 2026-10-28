# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A1 candidate code identity; no PCS/profile acceptance."""
from copy import deepcopy
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch
import tomllib
from identity import catalog, validate_catalog, parameters, encode, eval_row
from sampler import manifest, materialize, all_seeds_bound
from recursive import circle, sc, geometry, setup_bytes
from check_recursive import dense_word, base_generator


def rejects(call, reason):
    sc.rejects(call, reason)


def check():
    raw = Path(__file__).with_name('codes.toml').read_bytes()
    validate_catalog(raw)
    assert tomllib.loads(raw.decode()) == catalog()
    chunks = raw.split(b'[[code]]')
    for payload in (b'[[code]]'.join(chunks[:2]), b'[[code]]'.join([chunks[0],chunks[2],chunks[1]]), raw+b'\nversion=1\n', raw.replace(b'version = 1', b'version = true'),
                    raw.replace(b'proven = false', b'proven = true', 1),
                    raw.replace(b'seed_bits = 256', b'seed_bits = 272'),
                    raw.replace(b'exponents = [', b'exponents = [2, '),
                    raw.replace(b'2^256-all-seeds-v2', b'2^256-all-seeds-v1'),
                    raw.replace(b'proven = false\n', b'', 1),
                    raw.replace(b'version = 1', b'version = 1\nversion = 1'), raw+b' '*4096,
                    raw+b'\n[[code]]\nid="circle-m31/v1"\n', b'\xff'):
        rejects(lambda: validate_catalog(payload), 'InvalidRegistry')
    # Every authoritative field is checked, including type (True must not equal 1).
    parsed = catalog()
    import json
    for index, item in enumerate(parsed['code']):
        for key, value in item.items():
            if type(value) is bool:
                replacement = str(not value).lower()
            elif type(value) is int:
                replacement = str(value+1)
            elif type(value) is str:
                replacement = json.dumps(value+'x')
            else:
                replacement = json.dumps(value+[999])
            marker = (key+' = '+json.dumps(value)).encode()
            parts = raw.split(b'[[code]]')
            assert marker in parts[index+1], (index, key)
            parts[index+1] = parts[index+1].replace(marker, (key+' = '+replacement).encode(), 1)
            rejects(lambda: validate_catalog(b'[[code]]'.join(parts)), 'InvalidRegistry')
    base = base_generator()
    cases = 0
    identities = [b'stele/circle-m31/v1'+bytes([m, b]) for m in (0, 1, 3, 6) for b in (1, 2)]
    identities += [manifest(bytes(32), j) for j in (3, 4)]
    for raw_id in identities:
        for d in (1, 4, 8):
            info = parameters(raw_id, d)
            n, total = info['message_len'], info['codeword_len']
            row = [tuple((i*17+j*29+1) % sc.P for j in range(d)) for i in range(n)]
            word = encode(raw_id, d, row)
            if raw_id.startswith(b'stele/circle'):
                expected = list(zip(*(circle.encode(list(v), raw_id[-1]) for v in zip(*row))))
                assert info['distance'] == (total if n == 1 else total-n)
                assert info['setup_loss'] == 0 and info['setup_bytes'] == info['edge_count'] == 0
            else:
                setup, _ = materialize(raw_id)
                expected = dense_word(setup, row, base)
                assert info['distance'] == (64 if n == 64 else n//25+1)
                assert info['setup_loss'] == (0 if n == 64 else all_seeds_bound())
                assert info['setup_bytes'] == 43+8*info['edge_count']
            assert word == expected and len(word) == total
            columns = [total-1, 0, total//2, 0]
            assert eval_row(raw_id, d, row, columns) == [expected[c] for c in columns]
            # Returned metadata is not accepted as an input to encoding or re-resolution.
            original = deepcopy(info); info['distance'] = total; info['message_len'] = 1
            assert parameters(raw_id, d) == original and encode(raw_id, d, row) == word
            with patch('identity.materialize', side_effect=AssertionError('allocation before validation')), \
                 patch('identity.circle.encode', side_effect=AssertionError('FFT before validation')):
                assert eval_row(raw_id, d, row, []) == []
                rejects(lambda: encode(raw_id, d, row[:-1]), 'RowShape')
                rejects(lambda: encode(raw_id, d, None), 'RowShape')
                rejects(lambda: eval_row(raw_id, d, row, None), 'Column')
                rejects(lambda: encode(raw_id, d, [list(v) for v in row]), 'RowShape')
                for column in (-1, total, True):
                    rejects(lambda: eval_row(raw_id, d, row, [column]), 'Column')
                bad = list(row); bad[0] = (sc.P,)+(0,)*(d-1)
                rejects(lambda: encode(raw_id, d, bad), 'RowShape')
                bad[0] = (True,)+(0,)*(d-1)
                rejects(lambda: eval_row(raw_id, d, bad, []), 'RowShape')
            cases += 1
    # Resolve the entire supported size domain without constructing matrices/FFTs.
    with patch('identity.materialize', side_effect=AssertionError('descriptor allocated a setup')), \
         patch('identity.circle.encode', side_effect=AssertionError('descriptor allocated an FFT')):
        for d in (1, 4, 8):
            for b in (1, 2):
                for m in range(31-b):
                    p = parameters(b'stele/circle-m31/v1'+bytes([m, b]), d)
                    assert p['message_len'] == 1 << m and p['codeword_len'] == 1 << (m+b)
            for j in range(3, 16):
                p = parameters(manifest(bytes(32), j), d)
                edges = sum(rows*degree for k in range(4,j+1) for rows, _, degree in geometry(k))
                assert p['edge_count'] == edges and p['message_len'] == 4**j
    first, second = (manifest(bytes([i])+bytes(31), 4) for i in (0, 1))
    assert parameters(first, 1) == parameters(second, 1)
    row = [(int(i == 0),) for i in range(256)]
    assert encode(first, 1, row) != encode(second, 1, row)
    raw_graph = setup_bytes(materialize(manifest(bytes(32), 3))[0])
    for bad in (raw_graph, b'', b'stele/circle-m31/v1\x00\x00', b'stele/circle-m31/v1\x1e\x01',
                b'stele/circle-m31/v2\x06\x01', b'stele/circle-m31/v1\x06\x01\x00',
                b'stele/expander-seed/v1\x04'+bytes(32), bytes(32), bytearray(55)):
        rejects(lambda: parameters(bad, 1), 'InvalidCodeId')
    for d in (0, 2, 16, True):
        rejects(lambda: parameters(manifest(bytes(32), 4), d), 'FieldMismatch')
    rejects(lambda: encode(manifest(bytes(32),4),1,[(0,0)]*256), 'RowShape')
    assert parameters(manifest(bytes(32),15),8)['setup_loss'] == Fraction(200431782,1 << 160)
    print(f'{cases} identity-selected encoding/query cases pass; all 72 sizes resolve in three fields without setup allocation.')
    print('Registry field/type/identity substitutions reject; no PCS/profile parameters are admitted.')


if __name__ == '__main__':
    check()
