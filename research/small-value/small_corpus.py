"""RFC-0006 A5: shared A1 decisions with typed Small prover metadata."""
import copy
import json
import random
from pathlib import Path
import check_small_value as small
import corpus as a1
s = small.s
PATH = Path(__file__).with_name('corpus.jsonl')


def record(i, tables, proof):
    result = a1.encode_case(i, tables, proof)
    result.update(instance_hex=s.instance_bytes(i, len(i['sum'])).hex(),
                  round_hex=[s.message(i, r, row).hex() for r, row in enumerate(proof['rounds'])],
                  final_hex=s.message(i, len(i['ids']), proof['final']).hex())
    return result


def generate():
    cases = []
    rng = random.Random(2004001)
    for d in (4, 8):
        shapes = [(2,2),(3,2),(3,3),(4,2),(4,3),(4,4),(5,4)]
        for degree in range(5):
            for m,k in shapes:
                source = []
                for kind,lo,hi in [('signed',-32768,32767),('unsigned',0,65535),('signed',-32768,32767)]:
                    values = [lo,hi,0,1]+[rng.randint(lo,hi) for _ in range(2**m-4)]
                    source.append(dict(kind=kind, values=values))
                terms = [(tuple(rng.randrange(s.P) for _ in range(d)), [0]*degree),
                         (s.scalar(-7,d), []), (s.scalar(0,d), [1]*degree)]
                if degree: terms.append((tuple(rng.randrange(s.P) for _ in range(d)), [0,1] if degree>1 else [1]))
                cases.append(honest(f'd{d}-degree{degree}-m{m}-k{k}', d, m, k, source, terms))
        for constant in (0, 9):
            cases.append(honest(f'd{d}-empty{constant}', d, 4, 4, [],
                                [] if constant==0 else [(s.scalar(constant,d), [])]))
        zero = [dict(kind='unsigned', values=[0]*4)]
        base = honest(f'd{d}-unused-zero', d, 2, 2, zero, [])
        cases.append(base)
        bad = mutation(base, '-truncated-original', 'ClaimMismatch')
        bad['instances'][0]['tables'][0][0] = s.encode(s.scalar(65536,d)).hex()
        cases.append(bad)
    originals = list(cases)
    for case in originals:
        if case['expected'] != 'accept': continue
        d = case['field_degree']
        bad = mutation(case, '-round', 'RoundSumMismatch')
        row = bad['instances'][0]['proof']['rounds'][0]
        row[0] = s.encode(s.add(a1.decode(row[0],d),s.scalar(1,d))).hex()
        cases.append(bad)
        bad = mutation(case, '-shape', 'ProofShape')
        bad['instances'][0]['proof']['rounds'].pop()
        cases.append(bad)
        if case['instances'][0]['instance']['ids']:
            bad = mutation(case, '-unused-final', 'ClaimMismatch')
            final = bad['instances'][0]['proof']['final']
            final[-1] = s.encode(s.add(a1.decode(final[-1],d),s.scalar(1,d))).hex()
            cases.append(bad)
    assert len({case['name'] for case in cases}) == len(cases)
    return cases


def mutation(case, suffix, error):
    bad = copy.deepcopy(case)
    bad.update(name=case['name']+suffix, expected=error)
    for r in bad['instances']:
        for key in ('instance_hex','round_hex','final_hex'): r.pop(key, None)
    return bad


def honest(name, d, m, k, source, terms):
    public = name.encode()
    integers = [t['values'] for t in source]
    tables = [[s.scalar(v,d) for v in row] for row in integers]
    total = s.scalar(0,d)
    for column in range(2**m): total = s.add(total,s.compose(terms,[t[column] for t in tables],d))
    i = dict(id=204,m=m,ids=list(range(11,11+len(tables))),terms=terms,sum=total)
    pt, rt = s.Transcript(public,d), s.Transcript(public,d)
    proof, point = small.small_prove(pt,i,integers,k)
    assert (proof,point) == s.prove(rt,i,tables), name
    first = record(i,tables,proof)
    first['small'] = dict(k=k,tables=source)
    next_i = dict(id=205,m=1,ids=[41],terms=[(s.scalar(2,d),[0])],sum=s.scalar(16,d))
    next_tables = [[s.scalar(3,d),s.scalar(5,d)]]
    follow, follow_point = s.prove(pt,next_i,next_tables)
    assert (follow,follow_point) == s.prove(rt,next_i,next_tables)
    case = dict(name=name,field_degree=d,public_hex=public.hex(),expected='accept',
                instances=[first,record(next_i,next_tables,follow)])
    assert a1.evaluate(case).get('error','accept') == 'accept'
    return case


def check():
    cases = [json.loads(line) for line in PATH.read_text().splitlines()]
    assert cases == generate(), 'small corpus drift'
    for case in cases:
        result = a1.evaluate(case)
        assert result.get('error','accept') == case['expected'], (case['name'],result)
    print(f'{len(cases)} shared small-value decisions checked; no performance or profile claim')
