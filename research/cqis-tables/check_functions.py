# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q25: semantic function, representation and component-closure checks."""
import json
from pathlib import Path
import struct
import sys
from fractions import Fraction as Q
from blake3 import blake3
import function_identity as fn
import table_identity as table
from check_exp import reference, rejects


def report():
    functions = [fn.Function('exp_q/product',1,bytes([14,10,12,7])),
        fn.Function('exp_q/nearest',1,bytes([7,10,12])),
        fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',8,8,8,8,1,100000)),
        fn.Function('range_8',1,b''),fn.Function('silu_q',1,bytes([10,12])),
        fn.Function('softcap_q',1,struct.pack('<BBHB',10,12,3,1))]
    records = []
    for f in functions:
        expected = b'stele/v0.1/function/identity'+struct.pack('<H',len(f.name))+f.name.encode()
        expected += struct.pack('<IH',1,len(f.params))+f.params
        assert fn.encode(f) == expected and fn.decode(expected) == f
        assert fn.function_id(f) == blake3(expected).digest()
        for i in range(len(expected)):
            rejects('Function',lambda: fn.decode(expected[:i]))
        rejects('Function',lambda: fn.decode(expected+b'\0'))
        records.append(dict(name=f.name,descriptor=expected.hex(),function_id=fn.function_id(f).hex()))
    product,nearest,norm,ran,silu,cap = functions
    reps = [fn.Representation(product,1,b''),fn.Representation(nearest,0,b''),
            fn.Representation(nearest,2,bytes([6])),fn.Representation(norm,3,b''),
            fn.Representation(ran,0,b'')]
    representation_records = []
    for r in reps:
        raw = fn.encode_representation(r)
        deps = fn.dependencies(r)
        roles = {0:('exp_q/direct',) if r.function == nearest else ('range_8',),
                 1:('exp_q/hi','exp_q/lo'),2:('exp_q/hi','exp_q/lo','exp_q/correction'),
                 3:('rsqrt_q',)}[r.mode]
        assert tuple(d.name for d in deps) == roles
        expected = b'stele/v0.1/function/representation'+fn.function_id(r.function)
        expected += bytes([r.mode,len(r.params)])+r.params+bytes([len(deps)])
        expected += b''.join(table.table_id(d) for d in deps)
        assert raw == expected and fn.decode_representation(r.function,raw) == r
        fn.verify_representation(r,raw)
        for end in range(len(raw)):
            rejects('Representation',lambda: fn.decode_representation(r.function,raw[:end]))
        rejects('Representation',lambda: fn.decode_representation(r.function,raw+b'\0'))
        bad = bytearray(raw);bad[-1] ^= 1
        rejects('Representation',lambda: fn.decode_representation(r.function,bytes(bad)))
        if len(deps) > 1:
            offset = len(raw)-32*len(deps)
            swapped = raw[:offset]+raw[offset+32:offset+64]+raw[offset:offset+32]+raw[offset+64:]
            rejects('Representation',lambda: fn.decode_representation(r.function,swapped))
        rejects('FunctionIdentity',lambda: fn.decode_representation(cap,raw))
        representation_records.append(dict(function=r.function.name,mode=r.mode,
            parameters=r.params.hex(),encoding=raw.hex(),representation_id=fn.representation_id(r).hex()))
    assert fn.function_id(reps[1].function) == fn.function_id(reps[2].function)
    assert fn.representation_id(reps[1]) != fn.representation_id(reps[2])
    direct = table.canonical_rows(fn.dependencies(reps[1])[0])
    hi,lo,correction = [table.canonical_rows(d) for d in fn.dependencies(reps[2])]
    for index,t in enumerate(range(-128,1)):
        h,l = divmod(-t,64)
        reconstructed = hi[h][1]*lo[l][1]//4096+correction[index][1]
        assert reconstructed == direct[index][1] == reference(Q(-t,1024),4096)
    rejects('Representation',lambda: fn.verify_representation(reps[1],fn.encode_representation(reps[2])))
    assert fn.function_id(fn.Function('exp_q/product',1,bytes([14,10,12,6]))) != fn.function_id(product)
    for data in [struct.pack('<HBBBII',16,8,8,8,1,100000),
                 struct.pack('<HBBBII',8,9,8,8,1,100000),
                 struct.pack('<HBBBII',8,8,9,8,1,100000),
                 struct.pack('<HBBBII',8,8,8,9,1,100000),
                 struct.pack('<HBBBII',8,8,8,8,1,100001)]:
        assert fn.function_id(fn.Function('rmsnorm_q',1,data)) != fn.function_id(norm)
    rejects('Parameters',lambda: fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',8,8,8,8,2,200000)))
    rejects('FunctionName',lambda: fn.Function('exp_q/hi',1,bytes([14,10,12,7])))
    rejects('Version',lambda: fn.Function('range_8',True,b''))
    rejects('Representation',lambda: fn.Representation(ran,False,b''))
    rejects('Representation',lambda: fn.Representation(ran,0,bytearray()))
    assert fn.function_id(ran) != table.table_id(table.Descriptor('range_8',1,b''))
    for f,mode,params in [(product,0,b''),(product,1,b'\x07'),(nearest,1,b''),
                          (nearest,2,b'\x08'),(norm,0,b''),(ran,3,b''),(silu,2,b'\x07')]:
        rejects('Representation',lambda: fn.Representation(f,mode,params))
    selected = [reps[i] for i in (0,2,3,4)]
    manifest = fn.encode_manifest(selected)
    assert manifest == fn.encode_manifest(selected[::-1])
    fn.verify_manifest(selected,manifest)
    for i in [0,len(manifest)//2,len(manifest)-1]:
        bad = bytearray(manifest);bad[i] ^= 1
        rejects('Manifest',lambda: fn.verify_manifest(selected,bytes(bad)))
    rejects('Manifest',lambda: fn.verify_manifest(selected,manifest[:-1]))
    rejects('Manifest',lambda: fn.verify_manifest(selected,manifest+b'\0'))
    rejects('DuplicateFunction',lambda: fn.encode_manifest([reps[1],reps[2]]))
    rejects('Manifest',lambda: fn.verify_manifest([reps[i] for i in (0,1,3,4)],manifest))
    # Independent streaming read validates lengths, ordering and exact table closure.
    pos = len(b'stele/v0.1/cqis/functions')
    def take(n):
        nonlocal pos
        value = manifest[pos:pos+n];assert len(value) == n;pos += n;return value
    def sized():
        return take(int.from_bytes(take(2),'little'))
    count = int.from_bytes(take(4),'little');assert count == len(selected)
    functions_seen,components = [],{}
    for _ in range(count):
        f = fn.decode(sized());r = fn.decode_representation(f,sized())
        assert r in selected
        functions_seen.append(fn.function_id(f))
        for d in fn.dependencies(r): components[table.table_id(d)] = d
    assert functions_seen == sorted(set(functions_seen))
    count = int.from_bytes(take(4),'little');assert count == len(components)
    tables_seen = []
    for _ in range(count):
        d = table.decode(sized());tid = table.table_id(d)
        assert components[tid] == d
        assert take(32) == blake3(table.encode_data(d)).digest()
        tables_seen.append(tid)
    assert tables_seen == sorted(components) and pos == len(manifest)
    return dict(version=1,scope='research function/table closure; not a complete CQIS or passport identity',
        functions=records,representations=representation_records,
        manifest=dict(bytes=manifest.hex(),digest=blake3(manifest).hexdigest(),functions=len(selected)))


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('function-identity-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('function, representation and component closure checks pass; research only')
