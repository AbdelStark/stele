# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4"]
# ///
"""Q26 research checks; plaintext ranges are not cryptographic consumers."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from random import Random
import sys
import numpy as np
import limbs as m


def rejects(reason, call):
    try:
        call()
    except ValueError as error:
        assert str(error) == reason, (reason, str(error))
    else:
        raise AssertionError(f"accepted {reason}")


def oracle(spec):
    """Packed polynomial multiplication and prefix division, not convolution."""
    radix = 2**spec.radix_bits
    def caps(limit):
        values = []
        while limit or not values:
            values.append(min(radix-1, limit))
            limit //= radix
        return tuple(values)
    a, b = caps(spec.left_max), caps(spec.right_max)
    result_max = spec.count*spec.left_max*spec.right_max
    out = caps(result_max)
    columns = max(len(a)+len(b)-1, len(out))
    out += (0,)*(columns-len(out))
    # H exceeds every coefficient, so multiplication introduces no H carries.
    hbits = (spec.count*sum(a)*sum(b)).bit_length()+1
    packed = (sum(v << (hbits*i) for i,v in enumerate(a)) *
              sum(v << (hbits*i) for i,v in enumerate(b)) * spec.count)
    raw = tuple((packed >> (hbits*k)) % (1 << hbits) for k in range(columns))
    carries = (0,) + tuple(sum(raw[j]*radix**j for j in range(k))//radix**k
                          for k in range(1,columns)) + (0,)
    lhs = tuple(raw[k]+carries[k] for k in range(columns))
    rhs = tuple(out[k]+radix*carries[k+1] for k in range(columns))
    return dict(asdict(spec), prime=2**31-1, result_max=result_max,
                left_caps=a, right_caps=b, result_caps=out, carry_caps=carries,
                lhs=lhs, rhs=rhs)


def numpy_columns(left, right, bits):
    """Only small digits enter NumPy; wide source integers stay exact Python ints."""
    radix = 2**bits
    def digits(value):
        result = []
        while value or not result:
            result.append(value % radix)
            value //= radix
        return np.array(result,dtype=np.int64)
    rows = [np.convolve(digits(a),digits(b)) for a,b in zip(left,right)]
    total = np.zeros(max(map(len,rows)),dtype=np.int64)
    for row in rows:
        total[:len(row)] += row
    return sum(int(v)*radix**i for i,v in enumerate(total))


def rejects_malformed_limb_relations():
    # The API's trusted static spec is separate from every supplied field.
    spec = m.Spec(3,32768,32768,8)
    cert = m.derive(spec)
    for key,value in cert.items():
        wrong = dict(cert)
        wrong[key] = (value[0]+1,)+value[1:] if type(value) is tuple else value+1
        rejects('Certificate',lambda: m.validate(spec,wrong))
        wrong[key] = list(value) if type(value) is tuple else True
        rejects('Certificate',lambda: m.validate(spec,wrong))
    wrong = dict(cert,carry_caps=(False,)+cert['carry_caps'][1:])
    rejects('Certificate',lambda: m.validate(spec,wrong))
    rejects('Certificate',lambda: m.validate(spec,dict(cert,unknown=0)))
    rejects('Certificate',lambda: m.validate(spec,{k:v for k,v in cert.items() if k != 'prime'}))
    for bad in [replace(spec,count=0),replace(spec,count=2**32),
                replace(spec,left_max=-1),replace(spec,right_max=2**160),
                replace(spec,radix_bits=7),replace(spec,count=True)]:
        rejects('Spec',lambda: m.derive(bad))
    left, right = (32768,255,2),(32768,255,3)
    witness = m.witness(spec,left,right)
    check = lambda w: m.check_relations(spec,cert,left,right,w)
    assert check(witness) == sum(a*b for a,b in zip(left,right))
    out, carry = witness['result'], witness['carry']
    rejects('Relation',lambda: check(dict(witness,result=((out[0]+1)%256,)+out[1:])))
    rejects('Relation',lambda: check(dict(witness,carry=(0,carry[1]-1)+carry[2:])))
    rejects('Range',lambda: check(dict(witness,result=(out[0]+m.P,)+out[1:])))
    rejects('Range',lambda: check(dict(witness,carry=(0,carry[1]+m.P)+carry[2:])))
    rejects('Boundary',lambda: check(dict(witness,carry=(1,)+carry[1:])))
    rejects('Boundary',lambda: check(dict(witness,carry=carry[:-1]+(1,))))
    rejects('Witness',lambda: check(dict(witness,result=(True,)+out[1:])))
    a = witness['left']
    rejects('SourceDigits',lambda: check(dict(witness,left=((a[0][0]+1,)+a[0][1:],)+a[1:])))
    # M=257 admits digit caps (255,1), which also describe 511 > M.
    loose = m.Spec(1,0,257,8)
    loose_cert = m.derive(loose)
    assert loose_cert['right_caps'] == (255,1)
    forged = dict(left=((0,),),right=((255,1),),result=(0,0),carry=(0,0,0))
    rejects('InputRange',lambda: m.check_relations(loose,loose_cert,(0,),(511,),forged))
    rejects('InputRange',lambda: m.witness(spec,(True,0,0),(0,0,0)))
    rejects('InputRange',lambda: m.witness(spec,(0,),(0,)))
    # Rejection depends on the static format and shape, even for all-zero data.
    unsafe = m.Spec(65536,128,128,8)
    rejects('FieldBound',lambda: m.derive(unsafe))
    rejects('FieldBound',lambda: m.witness(unsafe,(0,)*65536,(0,)*65536))
    for bad in [m.Spec(16385,32768,32768,8),m.Spec(16384,65535,65535,8)]:
        rejects('FieldBound',lambda: m.derive(bad))
    zero = m.Spec(2**32-1,0,2**160-1,8)
    assert m.derive(zero) == oracle(zero)
    for bits in (4,8):
        largest = m.Spec(8,2**160-1,2**160-1,bits)
        row = (largest.left_max,)*8
        cert = m.derive(largest)
        assert cert == oracle(largest)
        assert m.check_relations(largest,cert,row,row,m.witness(largest,row,row)) == 8*(2**160-1)**2
        assert numpy_columns(row,row,bits) == 8*(2**160-1)**2


def report():
    rng, checksum = Random(2609),hashlib.sha256()
    accepted = 0
    for i in range(10000):
        count = rng.randrange(1,33) if i%2 else rng.randrange(1,2**32)
        a,b = (rng.getrandbits(rng.randrange(161)) for _ in range(2))
        spec = m.Spec(count,a,b,4 if i%3 else 8)
        expected = oracle(spec)
        safe = all(2*x < m.P for x in expected['lhs']+expected['rhs'])
        if safe:
            actual = m.derive(spec)
            assert actual == expected
            m.validate(spec,actual)
        else:
            rejects('FieldBound',lambda: m.derive(spec))
        checksum.update(json.dumps([expected,safe],sort_keys=True).encode())
        accepted += safe
    for i in range(10000):
        spec = m.Spec(rng.randrange(1,9),rng.getrandbits(rng.randrange(161)),
                      rng.getrandbits(rng.randrange(161)),4 if i%2 else 8)
        left = tuple(rng.randrange(spec.left_max+1) for _ in range(spec.count))
        right = tuple(rng.randrange(spec.right_max+1) for _ in range(spec.count))
        cert, witness = m.derive(spec),m.witness(spec,left,right)
        exact = sum(a*b for a,b in zip(left,right))
        assert m.check_relations(spec,cert,left,right,witness) == exact
        assert numpy_columns(left,right,spec.radix_bits) == exact
        checksum.update(json.dumps([asdict(spec),left,right,witness],sort_keys=True).encode())
    boundaries = []
    for count,maximum in [(65535,128),(16384,32768)]:
        spec = m.Spec(count,maximum,maximum,8)
        cert = m.derive(spec)
        # Actual endpoint rows and zero rows use the same static certificate.
        for value in (0,maximum):
            row = (value,)*count
            witness = m.witness(spec,row,row)
            assert m.check_relations(spec,cert,row,row,witness) == count*value**2
            assert numpy_columns(row,row,8) == count*value**2
        boundaries.append(dict(count=count,maximum=maximum,lhs=cert['lhs'],rhs=cert['rhs']))
    rejects_malformed_limb_relations()
    return dict(static_cases=10000,static_accepted=accepted,static_rejected=10000-accepted,
                witness_cases=10000,seed=2609,checksum=checksum.hexdigest(),boundaries=boundaries)


if __name__ == '__main__':
    result = report()
    encoded = json.dumps(result,indent=2,sort_keys=True)+'\n'
    path = Path(__file__).with_name('limbs.json')
    if sys.argv[1:] == ['--write']:
        path.write_text(encoded)
    else:
        assert not sys.argv[1:]
        assert path.read_text() == encoded
    print(encoded,end='')
