# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "numpy==2.3.4"]
# ///
"""RFC-0021 §§3,6: independent exact tanh-GeLU and normalizer evidence."""
from fractions import Fraction as Q
import json
from pathlib import Path
import random
import struct
import sys
from blake3 import blake3
import numpy as np
import certified_activations as act
import certified_gelu as gelu
from check_gelu import reference,normalizer_reference
import table_identity as identity


def report():
    normalizers = []
    for bits in (40,72,136,264):
        low,high = gelu.normalizer(bits)
        a,b = normalizer_reference(bits)
        assert max(low,a) < min(high,b)
        normalizers.append(dict(bits=bits,low=hex(int(low*(1 << bits))),
                                high=hex(int(high*(1 << bits)))))
    p = act.Parameters('gelu_tanh',8,8)
    d = identity.Descriptor('gelu_tanh_q',1,bytes([8,8]))
    raw = identity.encode_data(d)
    header = len(b'stele/v0.1/table/data')+41
    for t,(encoded_t,value) in zip(range(-32768,32768),struct.iter_unpack('<ii',raw[header:])):
        assert encoded_t == t and value == reference(p,t)
    rng,records = random.Random(2502033),bytearray()
    for i in range(10030):
        f,e,t = rng.randrange(31),rng.randrange(15),rng.randrange(-32768,32768)
        f = max(f,e)
        if i < 30:
            f,e,t = (0,1,30)[i//10],(0,14)[i//5%2],(-32768,-1,0,1,32767)[i%5]
        p = act.Parameters('gelu_tanh',f,e)
        expected = reference(p,t)
        overflow = not -32768 <= expected <= 32767
        if overflow:
            try:
                act.certify(p,t)
            except ValueError as error:
                assert str(error) == 'Overflow'
            else:
                raise AssertionError('accepted overflow')
        else:
            assert act.certify(p,t)['value'] == expected
        records.extend(struct.pack('<BBhBi',f,e,t,overflow,expected))
    inputs = np.array([rng.randrange(-32768,32768) for _ in range(10000)],dtype=np.int64)
    rows = np.frombuffer(raw[header:],dtype='<i4').reshape(65536,2).astype(np.int64)
    gathered = rows[inputs+32768,1]
    gathers = b''.join(struct.pack('<hh',int(t),int(y)) for t,y in zip(inputs,gathered))
    return dict(version=1,scope='native tanh-GeLU arithmetic; no proof or fidelity admission',
        normalizers=normalizers,data_digest=blake3(raw).hexdigest(),numpy_gathers=gathers.hex(),
        random_count=10000,boundary_count=30,
        layout='u8 F,E; i16le input; u8 overflow; i32le value',records=records.hex())


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('native-tanh-gelu.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,separators=(',',':'));output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('full tanh-GeLU bytes, 10000 varied entries, 30 boundaries and NumPy gathers match')
