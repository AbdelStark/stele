# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "numpy==2.3.4"]
# ///
"""RFC-0021 §6: full activation bytes and varied independent entry oracles."""
import json
from pathlib import Path
import random
import struct
import sys
from fractions import Fraction
from blake3 import blake3
import numpy as np
import certified_activations as act
from check_activations import reference
import table_identity as identity


def report():
    rng = random.Random(2502032)
    tables = []
    for p in [act.Parameters('sigmoid',8,12),act.Parameters('silu',8,8),
              act.Parameters('softcap',8,8,30,0)]:
        params = bytes([p.F,p.E])
        if p.kind == 'softcap':
            params += struct.pack('<HB',p.cap_m,p.cap_f)
        d = identity.Descriptor(p.kind+'_q',1,params)
        raw = identity.encode_data(d)
        header = len(b'stele/v0.1/table/data')+41
        for t,(encoded_t,value) in zip(range(-32768,32768),struct.iter_unpack('<ii',raw[header:])):
            assert encoded_t == t and value == reference(p,t)
        inputs = np.array([rng.randrange(-32768,32768) for _ in range(10000)],dtype=np.int64)
        rows = np.frombuffer(raw[header:],dtype='<i4').reshape(65536,2).astype(np.int64)
        gathered = rows[inputs+32768,1]
        gathers = b''.join(struct.pack('<hh',int(t),int(y)) for t,y in zip(inputs,gathered))
        tables.append(dict(name=d.name,parameters=params.hex(),data_digest=blake3(raw).hexdigest(),
                           numpy_gathers=gathers.hex()))
    records,counts = bytearray(),[]
    for kind_id,kind in enumerate(('sigmoid','silu','softcap')):
        for i in range(10030):
            f,e = rng.randrange(31),rng.randrange(15)
            if kind == 'silu':
                f = max(f,e)
            m,c = 0,0
            if kind == 'softcap':
                m,c = rng.randrange(1,32768),rng.randrange(e,31)
                while c and m % 2 == 0:
                    m //= 2;c -= 1
            t = rng.randrange(-32768,32768)
            if i < 30:
                f,e,t = (0,1,30)[i//10],(0,14)[i//5%2],(-32768,-1,0,1,32767)[i%5]
                if kind == 'softcap':
                    m,c = ((1,30),(65535,30),(65535,0))[i//10]
            p = act.Parameters(kind,f,e,m,c)
            value = reference(p,t)
            overflow = not -32768 <= value <= 32767
            if overflow:
                try:
                    act.certify(p,t)
                except ValueError as error:
                    assert str(error) == 'Overflow'
                else:
                    raise AssertionError('accepted overflow')
            else:
                assert act.certify(p,t)['value'] == value
            records.extend(struct.pack('<BBBH B h B i',kind_id,f,e,m,c,t,overflow,value))
        counts.append(dict(kind=kind,random_count=10000,boundary_count=30))
    # Integer-only NumPy half-away and one-sided rounding, including exact ties.
    ns = np.array([rng.randrange(-(1 << 30),1 << 30) for _ in range(10000)],dtype=np.int64)
    ds = np.array([rng.randrange(1,1 << 20) for _ in ns],dtype=np.int64)
    ns[::3] |= 1;ds[::3] = 2
    sides = np.array([rng.randrange(-1,2) for _ in ns],dtype=np.int64)
    magnitudes = np.abs(ns)
    values = (magnitudes//ds+(2*(magnitudes % ds) >= ds))*np.sign(ns)
    ties = 2*(magnitudes % ds) == ds
    values -= ties & (sides < 0) & (ns > 0)
    values += ties & (sides > 0) & (ns < 0)
    rounding = bytearray()
    for n,d,side,value in zip(ns,ds,sides,values):
        n,d,side,value = map(int,(n,d,side,value))
        assert act.round_endpoint(Fraction(n,d),side) == value
        rounding.extend(struct.pack('<iIbi',n,d,side,value))
    return dict(version=1,scope='native activation arithmetic; no proof or fidelity admission',
        tables=tables,counts=counts,numpy_rounding=rounding.hex(),
        layout='u8 kind,F,E; u16le cap_m; u8 cap_f; i16le input; u8 overflow; i32le expected',
        records=records.hex())


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('native-activation-entries.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,separators=(',',':'));output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('three full tables, 30000 varied entries, 90 boundaries, NumPy gathers/rounding match')
