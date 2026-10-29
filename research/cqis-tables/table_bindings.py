"""Draft RFC-0011 A2: exact public table/code/root records, research only."""
from functools import lru_cache
import importlib.util
from pathlib import Path
import struct
import sys
from blake3 import blake3
import function_identity as fn
import table_identity as table
from certified_exp import require

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'code-provenance'))
import identity as code_identity

spec = importlib.util.spec_from_file_location('cqis_binding_merkle',ROOT/'merkle/check_merkle.py')
merkle = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = merkle
spec.loader.exec_module(merkle)
P = (1 << 31)-1
PREFIX = b'stele/v0.1/passport/tables'


def validate_choices(reps,choices,other_tree_ids):
    _,components = fn.closure(reps)
    require(type(choices) is dict and set(choices) == {table.table_id(d) for d in components},'Closure')
    require(type(other_tree_ids) in (tuple,list)
            and all(type(v) is int and 0 <= v < 1 << 64 for v in other_tree_ids)
            and len(set(other_tree_ids)) == len(other_tree_ids),'TreeId')
    ids = set(other_tree_ids)
    for d in components:
        choice = choices[table.table_id(d)]
        require(type(choice) is tuple and len(choice) == 2,'CodeChoice')
        code,tree_id = choice
        require(type(code) is bytes,'CodeChoice')
        info = code_identity.parameters(code,1)
        require(info['message_len'] == table.shape(d)[1],'SourceShape')
        require(type(tree_id) is int and 0 <= tree_id < 1 << 64 and tree_id not in ids,'TreeId')
        ids.add(tree_id)
    return components


def tree_from_rows(d,code,tree_id,rows):
    """Arithmetic constructor for attack evidence; this does NOT admit table contents."""
    _,length,c = table.shape(d)
    info = code_identity.parameters(code,1)
    require(info['message_len'] == length,'SourceShape')
    require(type(tree_id) is int and 0 <= tree_id < 1 << 64,'TreeId')
    require(type(rows) is tuple and len(rows) == length
            and all(type(row) is tuple and len(row) == c
                    and all(type(v) is int and -(1 << 31) <= v < 1 << 31 for v in row) for row in rows),'Rows')
    # Only dimensions from the checked identity are used; no distance/proven/profile field.
    encoded = [code_identity.encode(code,1,[(row[j] % P,) for row in rows]) for j in range(c)]
    columns = [b''.join(struct.pack('<I',encoded[j][i][0]) for j in range(c))
               for i in range(info['codeword_len'])]
    tree = merkle.Tree(0,tree_id,len(columns),4*c)
    return columns,tree,merkle.build(tree,columns)


@lru_cache(maxsize=32,typed=True)
def derived_entry(d,code,tree_id):
    """Only canonical definition-derived rows reach the expected root."""
    data = table.encode_data(d)
    rows = table.decode_data(d,data)
    _,_,levels = tree_from_rows(d,code,tree_id,rows)
    return (table.table_id(d)+blake3(data).digest()+b'\x01'+struct.pack('<H',len(code))+code
            +struct.pack('<Q',tree_id)+levels[-1][0])


def encode(reps,choices,other_tree_ids):
    components = validate_choices(reps,choices,other_tree_ids)
    manifest = fn.encode_manifest(reps)
    return (PREFIX+blake3(manifest).digest()+struct.pack('<I',len(components))
            +b''.join(derived_entry(d,*choices[table.table_id(d)]) for d in components))


def verify(expected_reps,expected_choices,other_tree_ids,raw):
    require(type(raw) is bytes and raw == encode(expected_reps,expected_choices,other_tree_ids),'TableBindings')
