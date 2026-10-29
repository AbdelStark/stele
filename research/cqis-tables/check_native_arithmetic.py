#!/usr/bin/env python3
"""RFC-0021 §3: Python-int oracle for bounded native generator arithmetic."""
import json
from pathlib import Path
import random
import sys


def report():
    rng = random.Random(250203)
    rows = []
    for i in range(72):
        a = rng.getrandbits((1,31,32,33,64,127,256,511,1024,2048)[i%10])
        b = rng.getrandbits((1,32,65,128,255,512,1536)[i%7]) or 1
        if i >= 64:
            a = b = (1 << (1,31,32,33,64,127,256,1024)[i-64])-1
        shift = (0,1,31,32,33,127,513)[i%7]
        values = dict(a=a,b=b,add=a+b,sub=a-b if a>=b else None,mul=a*b,
                      quotient=a//b,remainder=a%b,left=a<<shift,right=a>>shift)
        rows.append(dict(shift=shift,**{k:None if v is None else format(v,'x') for k,v in values.items()}))
    return dict(version=1,scope='generator integer arithmetic only; no proof or control credit',cases=rows)


if __name__ == '__main__':
    data = report()
    path = Path(__file__).with_name('native-arithmetic-vectors.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            output.write('{"version":1,"scope":'+json.dumps(data['scope'])+',"cases":[\n')
            output.write(',\n'.join(json.dumps(row,separators=(',',':')) for row in data['cases']))
            output.write('\n]}\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == data
    print('72 independent exact large-integer cases checked')
