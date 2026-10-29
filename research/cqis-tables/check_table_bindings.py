# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q25: public table matrix/code/Merkle binding, not native protocol controls."""
import json
from pathlib import Path
import struct
import sys
from unittest.mock import patch
from blake3 import blake3
import table_bindings as binding
import table_identity as table
import function_identity as fn
from check_exp import rejects


def circle(m,b):
    return b'stele/circle-m31/v1'+bytes([m,b])


def report():
    nearest = fn.Function('exp_q/nearest',1,bytes([7,10,12]))
    product = fn.Function('exp_q/product',1,bytes([7,10,12,7]))
    norm = fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',8,8,8,8,1,100000))
    cases = [[fn.Representation(nearest,2,b'\x06'),fn.Representation(fn.Function('range_8',1,b''),0,b'')],
             [fn.Representation(product,1,b'')],[fn.Representation(norm,3,b'')]]
    records = []
    for case,reps in enumerate(cases):
        _,deps = fn.closure(reps)
        choices = {table.table_id(d):(circle(table.shape(d)[1].bit_length()-1,1+case%2),100+i)
                   for i,d in enumerate(deps)}
        if case == 0:
            d = next(d for d in deps if d.name == 'range_8')
            choices[table.table_id(d)] = (b'stele/expander-seed/v2\x04'+bytes(32),100+deps.index(d))
        raw = binding.encode(reps,choices,(1,2))
        binding.verify(reps,choices,(1,2),raw)
        assert binding.encode(reps[::-1],choices,(2,1)) == raw
        pos = len(b'stele/v0.1/passport/tables')
        assert raw[:pos] == b'stele/v0.1/passport/tables'
        assert raw[pos:pos+32] == blake3(fn.encode_manifest(reps)).digest();pos += 32
        count = int.from_bytes(raw[pos:pos+4],'little');pos += 4
        assert count == len(deps)
        layouts = []
        for d in deps:
            tid = table.table_id(d);code,tree_id = choices[tid]
            offset = pos
            assert raw[pos:pos+32] == tid;pos += 32
            assert raw[pos:pos+32] == blake3(table.encode_data(d)).digest();pos += 32
            assert raw[pos] == 1;pos += 1
            size = int.from_bytes(raw[pos:pos+2],'little');pos += 2
            assert size == len(code) and raw[pos:pos+size] == code;pos += size
            assert int.from_bytes(raw[pos:pos+8],'little') == tree_id;pos += 8
            root_offset = pos;root = raw[pos:pos+32];pos += 32
            rows = table.canonical_rows(d)
            columns,tree,levels = binding.tree_from_rows(d,code,tree_id,rows)
            assert root == levels[-1][0] and tree.width == 4*table.shape(d)[2]
            for i in (0,len(columns)//2,len(columns)-1):
                binding.merkle.verify(tree,root,i,columns[i],binding.merkle.path(levels,i))
            for at in (offset,offset+32,offset+64,offset+65,root_offset-8,root_offset):
                bad = bytearray(raw);bad[at] ^= 1
                rejects('TableBindings',lambda: binding.verify(reps,choices,(1,2),bytes(bad)))
            if case == 0 and d.name == 'exp_q/correction':
                # Membership under a wrong table's valid root is not definition binding.
                bad_rows = list(rows);bad_rows[0] = (rows[0][0],rows[0][1]+1)
                bad_columns,bad_tree,bad_levels = binding.tree_from_rows(d,code,tree_id,tuple(bad_rows))
                fake = bad_levels[-1][0]
                binding.merkle.verify(bad_tree,fake,0,bad_columns[0],binding.merkle.path(bad_levels,0))
                bad = raw[:root_offset]+fake+raw[root_offset+32:]
                rejects('TableBindings',lambda: binding.verify(reps,choices,(1,2),bad))
                # Alias has the same field matrix/root, but different forbidden integer bytes.
                alias = list(rows);alias[0] = (rows[0][0]+binding.P,rows[0][1])
                assert binding.tree_from_rows(d,code,tree_id,tuple(alias))[2][-1][0] == root
                data = table.encode_data(d);start = len(data)-len(rows)*2*4
                alias_data = data[:start]+struct.pack('<i',alias[0][0])+data[start+4:]
                rejects('Entry',lambda: table.decode_data(d,alias_data))
                bad = raw[:offset+32]+blake3(alias_data).digest()+raw[offset+64:]
                rejects('TableBindings',lambda: binding.verify(reps,choices,(1,2),bad))
                swapped = tuple((row[1],row[0]) for row in rows)
                assert binding.tree_from_rows(d,code,tree_id,swapped)[2][-1][0] != root
            layouts.append(dict(table=d.name,real=table.shape(d)[0],padded=len(rows),
                columns=table.shape(d)[2],code=code.hex(),tree_id=tree_id,root=root.hex()))
        assert pos == len(raw)
        changed_manifest = bytearray(raw);changed_manifest[len(binding.PREFIX)] ^= 1
        for bad in (raw[:-1],raw+b'\0',b'',bytes(changed_manifest)):
            rejects('TableBindings',lambda: binding.verify(reps,choices,(1,2),bad))
        tid = table.table_id(deps[0]);code,tree_id = choices[tid]
        with patch.object(binding.code_identity,'encode',side_effect=AssertionError('encoding before validation')):
            bad = dict(choices);bad[tid] = (circle(28,1),tree_id)
            rejects('SourceShape',lambda: binding.encode(reps,bad,(1,2)))
            bad = dict(choices);bad[tid] = (code,1)
            rejects('TreeId',lambda: binding.encode(reps,bad,(1,2)))
            for invalid_id in (True,-1,1 << 64):
                bad = dict(choices);bad[tid] = (code,invalid_id)
                rejects('TreeId',lambda: binding.encode(reps,bad,(1,2)))
            if len(deps) > 1:
                other = table.table_id(deps[1]);bad = dict(choices)
                bad[tid] = (code,choices[other][1])
                rejects('TreeId',lambda: binding.encode(reps,bad,(1,2)))
            bad = dict(choices);bad.pop(tid)
            rejects('Closure',lambda: binding.encode(reps,bad,(1,2)))
            bad = dict(choices);bad[bytes(32)] = (code,999)
            rejects('Closure',lambda: binding.encode(reps,bad,(1,2)))
            rejects('TreeId',lambda: binding.encode(reps,choices,(1,1)))
        records.append(dict(case=case,record=raw.hex(),digest=blake3(raw).hexdigest(),tables=layouts))
    empty = binding.PREFIX+blake3(fn.encode_manifest([])).digest()+bytes(4)
    assert binding.encode([],{},(1,2)) == empty
    binding.verify([],{},(1,2),empty)
    return dict(version=1,scope='research table/code/root record; no native passport or PCS admission',cases=records)


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('table-binding-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('canonical table matrices, code identities, Merkle contexts and binding mutations checked; research only')
