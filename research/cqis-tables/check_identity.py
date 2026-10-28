# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""Q25: candidate table descriptor and canonical data adversarial checks."""
import json
from pathlib import Path
import struct
import sys
from blake3 import blake3
import table_identity as identity
from check_exp import rejects


def report():
    definitions = [('exp_q/hi',bytes([14,10,12,7])),('exp_q/lo',bytes([14,10,12,7])),
        ('exp_q/direct',bytes([7,10,12])),('exp_q/correction',bytes([7,10,12,7])),
        ('silu_q',bytes([10,12])),('sigmoid_q',bytes([10,12])),
        ('gelu_q',bytes([10,12])),('gelu_tanh_q',bytes([10,12])),
        ('softcap_q',struct.pack('<BBHB',10,12,3,1)),('rsqrt_q',b''),
        ('range_8',b''),('range_12',b''),('range_16',b'')]
    records,ids = [],set()
    for name,params in definitions:
        d = identity.Descriptor(name,1,params)
        expected = b'stele/v0.1/table/identity'+len(name).to_bytes(2,'little')+name.encode('ascii')
        expected += (1).to_bytes(4,'little')+len(params).to_bytes(2,'little')+params
        assert identity.encode(d) == expected
        assert identity.decode(expected) == d
        digest = identity.table_id(d)
        assert digest == blake3(expected).digest() and digest not in ids
        ids.add(digest)
        for end in range(len(expected)):
            rejects('Descriptor',lambda: identity.decode(expected[:end]))
        rejects('Descriptor',lambda: identity.decode(expected+b'\0'))
        bad = bytearray(expected)
        bad[len(b'stele/v0.1/table/identity')] = 255
        rejects('Descriptor',lambda: identity.decode(bytes(bad)))
        rejects('Version',lambda: identity.Descriptor(name,2,params))
        records.append(dict(name=name,descriptor=expected.hex(),table_id=digest.hex()))
    for name,params in [('EXP_Q/HI',b''),('exp_q',bytes([14,10,12,7])),
                        ('rope_cos',b''),('sigmoid_q\0',bytes([10,12]))]:
        rejects('Name',lambda: identity.Descriptor(name,1,params))
    for params in (bytes([31,10,12,15]),bytes([14,10,12]),bytes([14,10,12,7,0])):
        rejects('Parameters',lambda: identity.Descriptor('exp_q/hi',1,params))
    rejects('Version',lambda: identity.Descriptor('range_8',True,b''))
    rejects('Parameters',lambda: identity.Descriptor('range_8',1,bytearray()))
    rejects('Parameters',lambda: identity.Descriptor('softcap_q',1,struct.pack('<BBHB',10,12,2,1)))
    rejects('Parameters',lambda: identity.Descriptor('exp_q/direct',1,bytes([16,10,12])))
    assert identity.table_id(identity.Descriptor('exp_q/hi',1,bytes([14,10,12,6]))) not in ids
    data_records = []
    for name,params in [definitions[i] for i in (0,1,2,3,5,9,10,11,12)]:
        d = identity.Descriptor(name,1,params)
        raw = identity.encode_data(d)
        rows = identity.decode_data(d,raw)
        n,padded,c = identity.shape(d)
        assert len(rows) == padded and all(len(row) == c for row in rows)
        offset = len(b'stele/v0.1/table/data')+32+4+4+1
        reference = b'stele/v0.1/table/data'+identity.table_id(d)+struct.pack('<IIB',n,padded,c)
        reference += b''.join(v.to_bytes(4,'little',signed=True) for row in rows for v in row)
        assert raw == reference
        for i,reason in [(len(b'stele/v0.1/table/data'),'Identity'),
                         (len(b'stele/v0.1/table/data')+32,'Shape'),(offset,'Entry')]:
            bad = bytearray(raw);bad[i] ^= 1
            rejects(reason,lambda: identity.decode_data(d,bytes(bad)))
        rejects('Length',lambda: identity.decode_data(d,raw[:-1]))
        rejects('Length',lambda: identity.decode_data(d,raw+b'\0'))
        rejects('DataHeader',lambda: identity.decode_data(d,b'X'+raw[1:]))
        bad = bytearray(raw);bad[len(b'stele/v0.1/table/data')+32:offset] = b'\xff'*9
        rejects('Shape',lambda: identity.decode_data(d,bytes(bad)))
        if rows[0][0] < 0:
            bad = bytearray(raw)
            bad[offset:offset+4] = struct.pack('<i',rows[0][0]+(1 << 31)-1)
            rejects('Entry',lambda: identity.decode_data(d,bytes(bad)))
        if padded > n:
            assert all(not any(row) for row in rows[n:])
            bad = bytearray(raw);bad[offset+n*c*4] = 1
            rejects('Padding',lambda: identity.decode_data(d,bytes(bad)))
        # A correctly shaped but reordered row vector still fails its definition.
        bad = raw[:offset]+raw[offset+c*4:offset+2*c*4]+raw[offset:offset+c*4]+raw[offset+2*c*4:]
        rejects('Entry',lambda: identity.decode_data(d,bad))
        data_records.append(dict(name=name,rows=n,padded=padded,columns=c,
            byte_length=len(raw),data_digest=blake3(raw).hexdigest()))
    # A syntactically valid descriptor does not admit a table that overflows.
    rejects('Overflow',lambda: identity.encode_data(identity.Descriptor('silu_q',1,bytes([0,14]))))
    return dict(version=1,scope='research identity/data bytes; no passport or lookup admission',
                descriptors=records,data=data_records)


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('table-identity-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2);output.write('\n')
    else:
        assert not sys.argv[1:]
        assert json.loads(path.read_text()) == result
    print('canonical descriptor/data bytes, full definition and padding checks pass; research only')
