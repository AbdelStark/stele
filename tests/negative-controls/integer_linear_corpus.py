"""RFC-0024 §6: current native execution against frozen independent full results.

The expensive reference campaigns already ran with the retained provenance.
This entry point regenerates every positive native proof and consumes every
distinct public request. It never treats an artifact digest as verification.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = '83bdafdeb83dbf9c0f4fea6755d6f5f8f9bec942bbbaa5c85044b31549ab8eaf'
ARCHIVE = '204cb6df7bec005aaa2b0d20802d98a66ef0f5937ed928297a4bd63a532cfaf2'
RECEIPT = ('integer linear corpus: 28 native complete proofs, 270 closed requests; QM31/OM31; '
           'frozen independent bytes, imports, records, usage and continuation; SHA256 '+ARCHIVE)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def run(command, **kwargs):
    try:
        return subprocess.run(command, check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        raise ValueError(f'{command[0]} failed: {(error.stderr or b"").decode(errors="replace")}') from error


def manifest(root):
    directory = root/'tests/negative-controls/fixtures/integer-linear'
    require(digest(directory/'manifest.json') == MANIFEST, 'Frozen manifest changed')
    value = decode((directory/'manifest.json').read_bytes())
    require(set(value['files']) == {'corpus.zip', 'provenance.json'}, 'Frozen payload inventory')
    require({p.name for p in directory.iterdir() if p.suffix != '.md'}
            == {'manifest.json', *value['files']}, 'Unlisted frozen payload')
    for name, expected in value['files'].items():
        require(not (directory/name).is_symlink() and digest(directory/name) == expected,
                f'Frozen payload changed: {name}')
    for name, expected in value['current_oracle_sources'].items():
        require(not (root/name).is_symlink() and digest(root/name) == expected,
                f'Independent source changed: {name}; requalify the affected evidence')
    require(value['files']['corpus.zip'] == ARCHIVE and value['rows'] == 270, 'Frozen corpus identity')
    return directory, value


def rows(directory, metadata):
    with zipfile.ZipFile(directory/'corpus.zip') as archive:
        require(archive.namelist() == metadata['encoding']['members'], 'Archive members')
        chunks = []
        with archive.open('chunks.bin') as source:
            while prefix := source.read(4):
                require(len(prefix) == 4, 'Chunk prefix')
                size, = struct.unpack('<I', prefix)
                require(0 < size <= 1024, 'Chunk size')
                chunk = source.read(size)
                require(len(chunk) == size, 'Truncated chunk')
                chunks.append(chunk)
        require(len(chunks) == metadata['encoding']['chunks']
                and sum(map(len, chunks)) == metadata['encoding']['chunk_payload_bytes'], 'Chunk inventory')

        def unpack(value):
            if isinstance(value, dict):
                result = {}
                for key, value in value.items():
                    if key.endswith('_hex'):
                        require(type(value) is list and all(type(i) is int and 0 <= i < len(chunks)
                                                           for i in value), 'Chunk reference')
                        result[key] = b''.join(chunks[i] for i in value).hex()
                    else:
                        result[key] = unpack(value)
                return result
            return [unpack(v) for v in value] if isinstance(value, list) else value

        with archive.open('rows.jsonl') as source:
            count = 0
            for line in source:
                row = decode(line)
                require(set(row) == {'request', 'expected'}, 'Corpus row')
                row['request'] = unpack(row['request'])
                yield row
                count += 1
            require(count == metadata['rows'], 'Corpus row count')


def check(root=ROOT):
    require(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'Python 3.12 without optimization required')
    directory, metadata = manifest(root)
    built = run(['cargo', 'build', '-p', 'stele-negative-controls', '--example',
                            'integer_linear_corpus', '--profile', 'test', '--locked', '--offline',
                            '--message-format=json-render-diagnostics'], cwd=root, capture_output=True)
    artifacts = [decode(line) for line in built.stdout.splitlines()]
    binaries = {a['executable'] for a in artifacts if a.get('reason') == 'compiler-artifact'
                and a['target']['name'] == 'integer_linear_corpus' and a['target']['kind'] == ['example']}
    require(len(binaries) == 1 and None not in binaries, 'Native corpus artifact')
    binary = binaries.pop()
    positives = {v['row']:v for v in metadata['positives']}
    require(len(positives) == len(metadata['positives']) == 28, 'Positive inventory')
    expected_rows = {}
    for group in metadata['groups'].values():
        for case in group:
            identity = (case['request_sha256'], case['expected_sha256'])
            require(expected_rows.setdefault(case['row'], identity) == identity, 'Frozen row alias')
    require(set(expected_rows) == set(range(metadata['rows'])), 'Uncovered frozen row')
    with tempfile.TemporaryDirectory(prefix='stele-integer-linear-corpus-') as temporary:
        requests, responses = (Path(temporary)/name for name in ('requests.jsonl','responses.jsonl'))
        with requests.open('wb') as output:
            for index, row in enumerate(rows(directory, metadata)):
                require(tuple(hashlib.sha256(canonical(row[k])).hexdigest() for k in ('request','expected'))
                        == expected_rows[index], f'Frozen row content: {index}')
                if index in positives:
                    case = positives[index]
                    produced = run([binary, str(case['degree']), case['case'], str(case['repetitions'])],
                                   cwd=root, capture_output=True)
                    require(canonical(decode(produced.stdout)) == canonical(dict(request=row['request'],
                            verification=row['expected'], producer_usage=case['producer_usage'])),
                            f'Native complete production: {case["case"]} K{case["degree"]} r{case["repetitions"]}')
                output.write(canonical(row['request'])+b'\n')
        with requests.open('rb') as input_, responses.open('wb') as output:
            run([binary, '--verify'], cwd=root, stdin=input_, stdout=output, stderr=subprocess.PIPE)
        with responses.open('rb') as actual:
            for index, (row, line) in enumerate(zip(rows(directory, metadata), actual, strict=True)):
                require(canonical(decode(line)) == canonical(row['expected']), f'Native closed consumption: {index}')
    print(RECEIPT)


if __name__ == '__main__':
    check()
