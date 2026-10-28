# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A1 bounded execution checks, not native memory/profile evidence."""
from collections import Counter
import struct
from unittest.mock import patch
import bounded
from bounded import requirements, encode, eval_row
from sampler import manifest, materialize
from recursive import encode_row, geometry, sc


def check():
    cases = 0
    for j in (3, 4, 5):
        raw = manifest(bytes([j])+bytes(31), j)
        setup, reference_blocks = materialize(raw)
        for d in (1, 4, 8):
            n = 4**j
            row = [tuple((i*17+k*29+1) % sc.P for k in range(d)) for i in range(n)]
            original = list(row)
            allocated, records = [], []
            allocate, block = bounded.zeros, bounded.block
            def zeros(length, degree):
                allocated.append(length)
                return allocate(length, degree)
            def recorded(*args):
                records.append(args[1:])
                return block(*args)
            with patch('bounded.zeros', side_effect=zeros), patch('bounded.block', side_effect=recorded), \
                 patch('sampler.materialize', side_effect=AssertionError('whole setup retained')):
                word, count = encode(raw, d, row)
            assert row == original and word == encode_row(setup, row)[0]
            plan = requirements(raw, d, 64)
            assert allocated == [2*n, sum(4**k for k in range(3,j))]
            assert count['scratch_peak'] == plan['scratch_slots']
            assert count['sparse_edges'] == plan['edges']
            assert count['hash_blocks'] == reference_blocks <= plan['hash_blocks_upper']
            assert len(records) == len(set(records)) == reference_blocks
            assert Counter((level,kind,r,stream) for level,kind,r,stream,counter in records).keys() == {
                (level,kind,r,stream) for level in range(4,j+1)
                for kind,(rows,_,_) in enumerate(geometry(level)) for r in range(rows) for stream in (0,1)}
            assert count['base_component_encodes'] == d
            assert count['sparse_limb_adds'] == count['sparse_limb_muls'] == d*plan['edges']
            columns = [2*n-1, 0, n, 0]
            assert eval_row(raw,d,row,columns) == [word[c] for c in columns]
            zero_word, zero_count = encode(raw,d,[sc.scalar(0,d)]*n)
            assert all(v == sc.scalar(0,d) for v in zero_word) and zero_count == count
            doubled = [sc.add(x,x) for x in row]
            assert encode(raw,d,doubled)[0] == [sc.add(x,x) for x in word]
            with patch('bounded.zeros', side_effect=AssertionError('allocation before validation')), \
                 patch('bounded.block', side_effect=AssertionError('sampling before validation')):
                assert eval_row(raw,d,row,[]) == []
                sc.rejects(lambda: encode(raw,d,row[:-1]), 'RowShape')
                sc.rejects(lambda: encode(raw,d,None), 'RowShape')
                bad = list(row); bad[0] = (sc.P,)+(0,)*(d-1)
                sc.rejects(lambda: encode(raw,d,bad), 'RowShape')
                for cols in (None, [-1], [2*n], [True]):
                    sc.rejects(lambda: eval_row(raw,d,row,cols), 'Column')
            cases += 1
    # Geometry-only checks cover every supported size without allocating an encoder.
    with patch('bounded.zeros', side_effect=AssertionError('capacity calculation allocated')):
        for j in range(3,16):
            for d in (1,4,8):
                raw = manifest(bytes(32),j)
                p = requirements(raw,d,64)
                scratch = [4**k for k in range(3,j)]
                assert p['scratch_slots'] == sum(scratch) == (4**j-64)//3
                assert p['rows'] == sum(rows for k in range(4,j+1) for rows,_,_ in geometry(k))
                assert p['edges'] == sum(rows*degree for k in range(4,j+1) for rows,_,degree in geometry(k))
                assert p['owned_payload_bytes'] == (2*4**j+sum(scratch)+128)*4*d+127*4+21*8
                assert p['input_bytes'] == 4**j*4*d
                query = requirements(raw,d,64,7)
                assert query['owned_payload_bytes'] == p['owned_payload_bytes']+7*4*d
                assert query['query_input_bytes'] == 7*8
                try:
                    small = requirements(raw,d,32)
                    assert small['owned_payload_bytes'] <= (1 << 31)-1
                except ValueError as error:
                    assert str(error) == 'Capacity'
                    assert (2*4**j+sum(scratch)+128)*4*d+127*4+21*4 > (1 << 31)-1
        assert requirements(manifest(bytes(32),13),1,32)['hash_blocks_upper'] > 1 << 32
        for selected in (-1,True,1 << 64,(1 << 63)-1):
            sc.rejects(lambda: requirements(manifest(bytes(32),4),1,64,selected), 'Capacity')
        for bits in (0,16,True):
            sc.rejects(lambda: requirements(manifest(bytes(32),4),1,bits), 'Capacity')
        sc.rejects(lambda: requirements(b'',1,64), 'InvalidCodeId')
        sc.rejects(lambda: requirements(manifest(bytes(32),4),2,64), 'FieldMismatch')
    # Exhaustion at an outer A, inner A, or late B rejects the whole operation.
    raw, row = manifest(bytes(32),5), [(1,)]*1024
    block = bounded.block
    for level,kind,index,stream in ((5,0,0,0),(4,0,0,1),(4,1,127,0),(5,1,511,1)):
        def exhausted(seed, l, k, r, s, counter):
            if (l,k,r,s) == (level,kind,index,stream):
                return bytes(32) if s == 0 else struct.pack('<8I', *([sc.P]*8))
            return block(seed,l,k,r,s,counter)
        with patch('bounded.block', side_effect=exhausted):
            sc.rejects(lambda: encode(raw,1,row), 'SamplingExhausted')
        assert row == [(1,)]*1024
    # Artificial zero coefficients test execution only, not an admitted setup/hash.
    def zero_coefficients(seed, level, kind, index, stream, counter):
        return bytes(32) if stream == 1 else block(seed,level,kind,index,stream,counter)
    with patch('bounded.block', side_effect=zero_coefficients):
        word, count = encode(raw,1,row)
        assert word == row+[(0,)]*1024
        assert count['sparse_edges'] == requirements(raw,1,64)['edges']
    print(f'{cases} bounded/reference cases in three fields; all sizes checked without allocation.')
    print('Zero rows retain every edge/draw; nested/late exhaustion rejects; no native RSS claim.')


if __name__ == '__main__':
    check()
