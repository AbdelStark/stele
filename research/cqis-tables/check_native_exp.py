#!/usr/bin/env python3
"""RFC-0021 §3: 10,000 native exp-entry vectors with two exact Python methods."""
from fractions import Fraction as Q
import json
from pathlib import Path
import random
import struct
import sys
from certified_exp import certify
from check_exp import reference


def report():
    rng = random.Random(2502031)
    records = bytearray()
    for i in range(10000):
        n,f,e = rng.randrange((1 << 31)+1),rng.randrange(31),rng.randrange(15)
        if i < 12:
            n,f,e = (0,1,1 << 31)[i%3],(0,30)[i//3%2],(0,14)[i//6]
        x = Q(n,1 << f)
        value = reference(x,1 << e)
        assert certify(x,e)['value'] == value
        records.extend(struct.pack('<IBBH',n,f,e,value))
    return dict(version=1,scope='exp entry arithmetic; not full lookup or model fidelity',
                count=10000,layout='u32le numerator, u8 F, u8 E, u16le value',records=records.hex())


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('native-exp-entries.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,separators=(',',':'));output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('10,000 exact exp-entry vectors checked against independent positive-series oracle')
