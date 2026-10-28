# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q22: sequential file positions/bytes, not physical disk traffic or peak RSS."""
from contextlib import ExitStack
from pathlib import Path
import os
import random
import struct
import tempfile

import check_windows as w

s = w.s


def reverse(index, bits):
    result = 0
    for _ in range(bits):
        result = 2 * result + (index & 1)
        index >>= 1
    return result


class Source:
    """Small research adapter; reference tables and visit logs belong to tests."""

    def __init__(self, paths, m, degree):
        if degree not in (4, 8) or not 0 <= m <= 8:
            raise ValueError('SourceShape')
        self.paths, self.m, self.degree = paths, m, degree
        self.receipts = []

    def blocks(self, point, width, visits):
        if width < 0 or len(point) + width > self.m:
            raise ValueError('SourceShape')
        d, n, count = self.degree, 2**self.m, len(self.paths)
        stride = 4 * d
        suffix_bits = self.m - len(point) - width
        read_bytes, scratch_cells = 0, 0
        with ExitStack() as stack:
            files = [stack.enter_context(path.open('rb', buffering=0)) for path in self.paths]
            if any(os.fstat(file.fileno()).st_size != n * stride for file in files):
                raise ValueError('SourceLength')
            for block in range(2**suffix_bits):
                suffix = reverse(block, suffix_bits)
                boolean = [[s.scalar(0, d)] * count for _ in range(2**width)]
                scratch_cells = max(scratch_cells, sum(map(len, boolean)))
                for offset in range(2**(len(point) + width)):
                    physical = block * 2**(len(point) + width) + offset
                    original = reverse(physical, self.m)
                    assert original % 2**suffix_bits == suffix
                    prefix = original >> (self.m - len(point))
                    window = (original >> suffix_bits) % 2**width
                    eq = w.weight(point, prefix, d)
                    for table, file in enumerate(files):
                        assert file.tell() == physical * stride
                        raw = file.read(stride)
                        if len(raw) != stride:
                            raise ValueError('SourceLength')
                        value = struct.unpack('<' + 'I' * d, raw)
                        if any(limb >= s.P for limb in value):
                            raise ValueError('SourceField')
                        read_bytes += len(raw)
                        visits.append((table, original))
                        boolean[window][table] = s.add(boolean[window][table], s.mul(eq, value))
                yield suffix, boolean
            if any(file.read(1) for file in files):
                raise ValueError('SourceLength')
        assert read_bytes == count * n * stride
        self.receipts.append((read_bytes, scratch_cells))


def checks():
    rng, cases = random.Random(3052), 0
    schedules = [(0, []), (2, []), (2, [1]), (3, [1, 1]), (3, [2]), (3, [1, 2]), (4, [2, 1])]
    with tempfile.TemporaryDirectory() as directory:
        paths = [Path(directory) / str(table) for table in range(3)]
        for d in (4, 8):
            for delta in range(5):
                for m, windows in schedules:
                    tables = [[tuple(rng.randrange(s.P) for _ in range(d)) for _ in range(2**m)]
                              for _ in paths]
                    # Preparation intentionally uses resident reference inputs; it is not free.
                    for path, table in zip(paths, tables):
                        path.write_bytes(b''.join(s.encode(table[reverse(j, m)]) for j in range(2**m)))
                    factors = [v % 2 for v in range(delta)]
                    terms = [(tuple(rng.randrange(s.P) for _ in range(d)), factors), (s.scalar(-3, d), [])]
                    if delta:
                        terms.append((s.scalar(0, d), [1]*delta))
                    total = s.scalar(0, d)
                    for row in zip(*tables):
                        total = s.add(total, s.compose(terms, row, d))
                    instance = {'id': cases, 'm': m, 'ids': [11, 12, 13], 'terms': terms, 'sum': total}
                    source = Source(paths, m, d)
                    a, b, c = [s.Transcript(b'sequential-source-research', d) for _ in range(3)]
                    proof, point, scans = w.window_prove(a, instance, tables, windows, blocks=source.blocks)
                    reference, expected = s.prove(b, instance, tables)
                    assert (proof, point) == (reference, expected)
                    assert s.verify_public(c, instance, proof, tables)['point'] == point
                    assert s.challenge(a) == s.challenge(b) == s.challenge(c)
                    assert len(source.receipts) == len(windows) + 1
                    for (read_bytes, cells), width, scan in zip(source.receipts, windows + [0], scans):
                        assert read_bytes == len(paths) * 2**m * 4*d
                        assert cells == len(paths) * 2**width
                        assert sorted(scan) == [(table, j) for table in range(3) for j in range(2**m)]
                        for table in range(3):
                            assert [j for a, j in scan if a == table] == [reverse(j, m) for j in range(2**m)]
                    if m == 3 and windows == [1, 2]:
                        saved = paths[-1].read_bytes()
                        changed = s.add(tables[-1][0], s.scalar(1, d))
                        paths[-1].write_bytes(s.encode(changed) + saved[4*d:])
                        forged, _, _ = w.window_prove(s.Transcript(b'sequential-source-research', d), instance,
                                                     tables, windows, blocks=Source(paths, m, d).blocks)
                        assert forged['rounds'] == proof['rounds']
                        assert sum(x != y for x, y in zip(forged['final'], proof['final'])) == 1
                        s.rejects(lambda: s.verify_public(s.Transcript(b'sequential-source-research', d),
                                                          instance, forged, tables), 'ClaimMismatch')
                        paths[-1].write_bytes(saved)
                    cases += 1
            # Length and canonical-limb rejection use the real file reader.
            saved = paths[0].read_bytes()
            for malformed, error in [(saved[:-1], 'SourceLength'), (saved+b'\0', 'SourceLength'),
                                     (struct.pack('<I', s.P)+saved[4:], 'SourceField')]:
                paths[0].write_bytes(malformed)
                s.rejects(lambda: list(Source(paths, m, d).blocks([], 1, [])), error)
            paths[0].write_bytes(saved)
            s.rejects(lambda: Source(paths, 9, d), 'SourceShape')
            s.rejects(lambda: list(Source(paths, m, d).blocks([], m+1, [])), 'SourceShape')
        for d in (4, 8):
            instance = {'id': 100, 'm': 3, 'ids': [], 'terms': [(s.scalar(9, d), [])], 'sum': s.scalar(72, d)}
            source = Source([], 3, d)
            a, b, c = [s.Transcript(b'empty-source', d) for _ in range(3)]
            proof, point, _ = w.window_prove(a, instance, [], [1, 1], blocks=source.blocks)
            assert (proof, point) == s.prove(b, instance, [])
            assert s.verify_public(c, instance, proof, [])['point'] == point
            assert s.challenge(a) == s.challenge(b) == s.challenge(c)
            assert source.receipts == [(0, 0)] * 3
    print(f'{cases+2} both-field sequential-file/dense/public-consumer cases and continuations agree')
    print('Each visit reads a*N*4*d bytes at consecutive file positions, without seeks; OS cache traffic is not measured')
    print('10 changed-unused-source cases reject ClaimMismatch; malformed lengths/limbs reject; research only')


if __name__ == '__main__':
    checks()
