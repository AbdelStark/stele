# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0006 A5 research for E3-04; no production/control or performance credit.
Question: does a base-field prefix grid preserve A1 bytes for K coefficients?
Kill criterion: any proof, claim, or continuation disagreement with dense A1.
"""
import itertools
import random
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sumcheck'))
import check_sumcheck as s


def extend_axis_by_axis(boolean, k, width):
    grid=[v%s.P for v in boolean]
    for h in range(k):
        suffix=2**(k-h-1)
        out=[]
        for prefix in range(width**h):
            offset=prefix*2*suffix
            for node in range(width):
                out.extend((grid[offset+z]+node*(grid[offset+suffix+z]-grid[offset+z]))%s.P for z in range(suffix))
        grid=out
    return grid


def term_grid(i, integers, k, d):
    width=max(2,s.degree(i)+1)
    suffix=2**(i['m']-k)
    result=[s.scalar(0,d)]*(width**k)
    for coefficient,factors in i['terms']:
        accumulated=[0]*(width**k)
        for z in range(suffix):
            grids=[extend_axis_by_axis([integers[f][b*suffix+z] for b in range(2**k)],k,width) for f in factors]
            for index in range(width**k):
                product=1
                for grid in grids:product=product*grid[index]%s.P
                accumulated[index]=(accumulated[index]+product)%s.P
        result=[s.add(total,s.mul(coefficient,s.scalar(v,d))) for total,v in zip(result,accumulated)]
    return result


def small_prove(t, i, integers, k):
    d, delta, m = t.degree, s.degree(i), i['m']
    assert 0 <= k <= min(4, m)
    # Candidate construction boundary: representation fixes magnitude statically.
    assert all(-32768 <= x <= 65535 for table in integers for x in table)
    width = max(2, delta + 1)
    suffix = 2**(m-k)
    grid = []
    for nodes in itertools.product(range(width), repeat=k):
        weights = []
        for b in range(2**k):
            w = 1
            for h, x in enumerate(nodes):
                w = w * (x if b >> (k-h-1) & 1 else 1-x) % s.P
            weights.append(w)
        accumulators = [0] * len(i['terms'])
        for z in range(suffix):
            values = [sum(w * table[b*suffix+z] for b,w in enumerate(weights)) % s.P for table in integers]
            for index, (_, factors) in enumerate(i['terms']):
                product = 1
                for f in factors:
                    product = product * values[f] % s.P
                accumulators[index] = (accumulators[index] + product) % s.P
        total = s.scalar(0,d)
        for (coefficient,_), value in zip(i['terms'],accumulators):
            total = s.add(total,s.mul(coefficient,s.scalar(value,d)))
        grid.append(total)
    optimized=term_grid(i,integers,k,d)
    assert optimized==grid, 'term grid differs from direct prefix evaluation'
    grid=optimized
    t.absorb(s.INSTANCE,s.instance_bytes(i,d))
    rounds, point = [], []
    for r in range(k):
        tail = width**(k-r-1)
        values=[]
        for node in range(delta+1):
            total=s.scalar(0,d)
            for bits in itertools.product((0,1),repeat=k-r-1):
                index=node
                for b in bits:index=index*width+b
                total=s.add(total,grid[index])
            values.append(total)
        rounds.append(values)
        t.absorb(s.ROUND,s.message(i,r,values))
        point.append(s.challenge(t))
        grid=[s.interpolate([grid[b*tail+z] for b in range(width)],point[-1]) for z in range(tail)]
    # Direct prefix dot products: never allocate a full K input copy.
    weights=[]
    for b in range(2**k):
        w=s.scalar(1,d)
        for h,x in enumerate(point):
            w=s.mul(w,x if b>>(k-h-1)&1 else s.add(s.scalar(1,d),s.neg(x)))
        weights.append(w)
    state=[]
    for table in integers:
        output=[]
        for z in range(suffix):
            value=s.scalar(0,d)
            for b,w in enumerate(weights):value=s.add(value,s.mul(w,s.scalar(table[b*suffix+z],d)))
            output.append(value)
        state.append(output)
    for r in range(k,m):
        values=[]
        for node in range(delta+1):
            folded=[s.fold(table,s.scalar(node,d)) for table in state]
            total=s.scalar(0,d)
            for z in range(2**(m-r-1)):
                total=s.add(total,s.compose(i['terms'],[table[z] for table in folded],d))
            values.append(total)
        rounds.append(values)
        t.absorb(s.ROUND,s.message(i,r,values))
        point.append(s.challenge(t))
        state=[s.fold(table,point[-1]) for table in state]
    final=[table[0] for table in state]
    t.absorb(s.FINAL,s.message(i,len(i['ids']),final))
    return {'rounds':rounds,'final':final},point


def checks():
    rng=random.Random(2004)
    count=0
    for d in (4,8):
        for delta in range(5):
            for m,k in [(0,0),(1,1),(2,2),(3,2),(3,3),(4,4),(5,4)]:
                integers=[]
                for table_index in range(3):
                    lo,hi=(-32768,32767) if table_index%2==0 else (0,65535)
                    integers.append([rng.choice([lo,hi,0,1,rng.randint(lo,hi)]) for _ in range(2**m)])
                terms=[(tuple(rng.randrange(s.P) for _ in range(d)),[0]*delta),(s.scalar(-3,d),[])]
                if delta:terms += [(tuple(rng.randrange(s.P) for _ in range(d)),[1]*delta),(s.scalar(0,d),[0]*delta)]
                tables=[[s.scalar(x,d) for x in table] for table in integers]
                total=s.scalar(0,d)
                for row in zip(*tables):total=s.add(total,s.compose(terms,row,d))
                i={'id':count,'m':m,'ids':[11,12,13],'terms':terms,'sum':total}
                a,b,c=[s.Transcript(b'small-prefix-research',d) for _ in range(3)]
                proof,point=small_prove(a,i,integers,k)
                reference,expected=s.prove(b,i,tables)
                assert (proof,point)==(reference,expected),(d,delta,m,k)
                receipt=s.verify_public(c,i,proof,tables)
                assert receipt['point']==point
                assert s.challenge(a)==s.challenge(b)==s.challenge(c)
                count+=1
    print(f'{count} prefix-grid/dense/public-consumer cases agree in both fields, degrees 0..4, full-extension coefficients, signed/unsigned extrema, unused inputs and maximum prefix with tail.',flush=True)

def rejects_truncated_original():
    for d in (4,8):
        i={'id':204,'m':2,'ids':[11],'terms':[],'sum':s.scalar(0,d)}
        original=[[s.scalar(x,d) for x in [65536,0,0,0]]]
        honest,_=s.prove(s.Transcript(b'small-control-research',d),i,original)
        s.verify_public(s.Transcript(b'small-control-research',d),i,honest,original)
        forged,_=small_prove(s.Transcript(b'small-control-research',d),i,[[0,0,0,0]],2)
        assert forged['rounds']==honest['rounds']
        assert len(forged['final'])==1 and forged['final'][0]!=honest['final'][0]
        s.rejects(lambda:s.verify_public(s.Transcript(b'small-control-research',d),i,forged,original),'ClaimMismatch')
    print('Both-field one-value truncation misuse rejected with ClaimMismatch; research only.',flush=True)

if __name__=='__main__':
    if sys.argv[1:]:
        import json
        import small_corpus
        assert sys.argv[1:] in (['--write-corpus'], ['--check-corpus']), 'unknown arguments'
        if sys.argv[1:] == ['--write-corpus']:
            with small_corpus.PATH.open('x') as output:
                output.write(''.join(json.dumps(case,sort_keys=True)+'\n' for case in small_corpus.generate()))
        small_corpus.check()
        sys.exit(0)
    checks()
    rejects_truncated_original()
