# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4"]
# ///
"""Q26: exact scale fusion, NumPy integer parity and tied embedding witness."""
from fractions import Fraction as Q
import hashlib
import json
from pathlib import Path
import random
import sys
import numpy as np
import alignment as a
import quantiser as q
from check_quantiser import nearest
from check_scalars import rejects


def numpy_shift(products, shifts):
    """Independent uint64 quotient/remainder and range-first left shifts."""
    mag = np.abs(products).astype(np.uint64)
    right = np.clip(shifts,0,63).astype(np.uint64)
    quotient = np.right_shift(mag,right)
    rem = mag-np.left_shift(quotient,right)
    half = np.left_shift(np.uint64(1),np.clip(shifts-1,0,62).astype(np.uint64))
    rounded = quotient+((shifts > 0) & (rem >= half)).astype(np.uint64)
    rounded = np.where(shifts >= 64,np.uint64(0),rounded)
    limit = np.where(products < 0,32768,32767).astype(np.uint64)
    left = np.clip(-shifts,0,16).astype(np.uint64)
    fits = mag <= np.right_shift(limit,left)
    safe = np.where(fits,mag,np.uint64(0))
    rounded = np.where(shifts < 0,np.left_shift(safe,left),rounded)
    valid = np.where(shifts < 0,fits,rounded <= limit)
    return rounded.astype(np.int64)*np.sign(products),valid


def decision(call, expected):
    if -32768 <= expected <= 32767:
        assert call() == expected
        return 1
    rejects('Overflow',call)
    return 0


def report():
    rng, checksum = random.Random(2603),hashlib.sha256()
    cases,products,shifts = [],[],[]
    for i in range(20000):
        mode = 'dynamic' if i % 2 == 0 else 'static'
        acc,mw = rng.randrange(-(1 << 31),1 << 31),rng.randrange(1,65536)
        sx = rng.randrange(0,260) if mode == 'dynamic' else rng.randrange(1,65536)
        if sx == 0: acc = 0
        fx,fo = rng.randrange(31),rng.randrange(31)
        ew = rng.randrange(-1099,1025) if i % 3 == 0 else rng.randrange(-64,16)
        args = (acc,mw,sx,ew,fx,fo,mode)
        cases.append(args); products.append(acc*mw*sx); shifts.append(fx-ew-fo)
    values,valid = numpy_shift(np.array(products,dtype=np.int64),np.array(shifts,dtype=np.int64))
    accepted = 0
    for args,ny,ok in zip(cases,values,valid):
        acc,mw,sx,ew,fx,fo,_ = args
        expected = nearest(Q(acc*mw*sx)*Q(2)**(ew-fx+fo))
        success = decision(lambda: a.matmul_output(*args),expected)
        assert bool(ok) == bool(success)
        if success: assert int(ny) == expected
        checksum.update(json.dumps([args,expected,success],separators=(',',':')).encode())
        accepted += success
    residual_ok = 0
    for _ in range(10000):
        x,y = rng.randrange(-32768,32768),rng.randrange(-32768,32768)
        fl,fr,fo = rng.randrange(31),rng.randrange(31),rng.randrange(31)
        expected = nearest((Q(x)*Q(2)**-fl+Q(y)*Q(2)**-fr)*Q(2)**fo)
        common = max(fl,fr,fo)
        total = np.int64(x)*(np.int64(1) << (common-fl))+np.int64(y)*(np.int64(1) << (common-fr))
        nv,ok = numpy_shift(np.array([total]),np.array([common-fo]))
        success = decision(lambda: a.residual(x,fl,y,fr,fo),expected)
        assert bool(ok[0]) == bool(success)
        if success: assert int(nv[0]) == expected
        checksum.update(json.dumps([x,fl,y,fr,fo,expected,success]).encode())
        residual_ok += success
    # One shared record, row scales indexed by vocabulary for gather and LM head.
    source = [[Q(1),Q(2)],[Q(3),Q(5)]]
    weight = q.weights(source,8)
    transposed = q.weights([list(v) for v in zip(*source)],8)
    column_codes = [list(v) for v in zip(*transposed['output'])]
    assert weight['output'] != column_codes
    tied_cases = 0
    records = [q.weights(source,b) for b in (4,8)]
    for i in range(10000):
        selected = records[i%2]
        token = rng.randrange(2)
        codes,m,ew = selected['output'][token],selected['mantissas'][token],selected['exponent']
        gathered = [a.round_i16(v*m,-ew-8) for v in codes]
        assert gathered == [nearest(Q(v*m)*Q(2)**(ew+8)) for v in codes]
        row = [rng.randrange(-128,129) for _ in codes]
        converted = q.dynamic(row)
        logits = []
        for codes,m in zip(selected['output'],selected['mantissas']):
            acc = sum(x*w for x,w in zip(converted['output'],codes))
            actual = a.matmul_output(acc,m,converted['scale'],ew,8,8,'dynamic')
            real = sum(Q(x*converted['scale'],256)*Q(w*m)*Q(2)**ew
                       for x,w in zip(converted['output'],codes))
            assert actual == nearest(256*real)
            logits.append(actual)
        checksum.update(json.dumps([i%2,token,gathered,row,logits]).encode())
        tied_cases += 1
    assert a.residual(1,1,1,1,0) == 1  # Separate half-away conversion would give 2.
    assert a.residual(32767,0,-32767,0,30) == 0  # Preserve cancellation before range check.
    assert a.matmul_output(1,65535,259,-20,0,0,'dynamic') == 16
    assert a.matmul_output(0,1,0,1024,0,30,'dynamic') == 0
    assert a.round_i16(-1,-15) == -32768
    rejects('Overflow',lambda: a.round_i16(1,-15))
    for acc in (-(1 << 31),-1,0,1,(1 << 31)-1):
        for ew in (-1099,-64,-63,0,1,16,1024):
            args = (acc,65535,65535,ew,0,0,'static')
            expected = nearest(Q(acc*65535**2)*Q(2)**ew)
            ny,ok = numpy_shift(np.array([acc*65535**2],dtype=np.int64),np.array([-ew],dtype=np.int64))
            success = decision(lambda: a.matmul_output(*args),expected)
            assert bool(ok[0]) == bool(success)
            if success: assert int(ny[0]) == expected
    rejects('ZeroScale',lambda: a.matmul_output(1,1,0,0,0,0,'dynamic'))
    rejects('InputScale',lambda: a.matmul_output(0,1,0,0,0,0,'static'))
    for args,reason in [((True,1,1,0,0,0,'static'),'Accumulator'),
                        ((0,0,1,0,0,0,'static'),'WeightScale'),
                        ((0,1,260,0,0,0,'dynamic'),'InputScale'),
                        ((0,1,1,1025,0,0,'static'),'WeightExponent'),
                        ((0,1,1,0,31,0,'static'),'FractionalBits'),
                        ((0,1,1,0,0,0,'fallback'),'Mode')]:
        rejects(reason,lambda: a.matmul_output(*args))
    return dict(version=1,scope='research scale alignment and tied storage; no native inference or certificate admission',
                matmul_cases=20000,matmul_accepted=accepted,residual_cases=10000,residual_accepted=residual_ok,
                tied_cases=tied_cases,tied_witness=dict(source=[[1,2],[3,5]],row_codes=weight['output'],
                    separately_transposed_codes=column_codes),sha256=checksum.hexdigest())


if __name__ == '__main__':
    result = report()
    path = Path(__file__).with_name('alignment-candidates.json')
    if sys.argv[1:] == ['--write']:
        with path.open('x') as output:
            json.dump(result,output,indent=2); output.write('\n')
    else:
        assert not sys.argv[1:] and json.loads(path.read_text()) == result
    print('20000 fused scale, 10000 residual and 10000 tied embedding/LM-head cases checked exactly')
