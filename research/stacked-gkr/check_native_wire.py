# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0006 A4 native public bytes/consumers against independent A1/A7 references."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from blake3 import blake3
from check_statement import fixture
from check_stage import claim
from check_weighted_mle import boolean_table
import stage
from statement import encode, field, need

ROOT = Path(__file__).resolve().parents[2]
SOURCES = b'stele/v0.1/gkr/stacked-sources'
PUBLIC = b'stacked wire oracle'
sc = stage.sc


class Transcript(stage.Transcript):
    def absorb(self, label, payload):
        if label == SOURCES:
            self.state = blake3(self.state+b'\0'+struct.pack('<I', len(label))+label
                                +struct.pack('<Q', len(payload))+payload).digest()
        else:
            super().absorb(label, payload)


def sources(s, tables):
    # A4's stricter identity rule is separate from the historical study's codec.
    source = s['coefficient']['source_id']
    need(source is None or source not in [s['output']['id'], s['coefficient_id'], *s['inputs']])
    stage.public_tables(s, tables)
    return struct.pack('<BBQI', 1, 0, s['id'], len(tables))+b''.join(
        struct.pack('<Q', identity)+b''.join(field(x, s['field']) for x in table)
        for identity, table in zip(s['inputs'], tables))


def verify(s, tables, proof):
    t = Transcript(PUBLIC, s['field'])
    t.absorb(SOURCES, sources(s, tables))
    result = stage.verify_public(t, s, proof, tables)
    return result, t


def outcome(s, tables, proof):
    try:
        result, t = verify(s, tables, proof)
    except ValueError as error:
        name = str(error)
        if name in ('ProofShape', 'RoundSumMismatch', 'FinalEvaluationMismatch'):
            name = 'Sumcheck('+name+')'
        return {'decision': name}
    i, d = stage.instance(s), s['field']
    return dict(decision='accept', stack=encode(s).hex(), sources=sources(s, tables).hex(),
                instance=sc.instance_bytes(i, d).hex(),
                proof=[sc.message(i, r, row).hex() for r, row in enumerate(proof['rounds'])]
                      +[sc.message(i, len(i['ids']), proof['final']).hex()],
                point=[field(x, d).hex() for x in result['point']],
                claims=[[identity, field(x, d).hex()] for identity, x in result['claims']],
                sc=result['sc'], continuation=t.challenge()[0].hex())


def cases():
    for d in (4, 8):
        for kind in range(6):
            for order in (0, 1):
                s = fixture(d, kind, order, True)
                if kind == 4:
                    s['layout'][2] = (2, 1)  # Three real heads share one group.
                s['terms'] = [(tuple(range(2, 2+d)), [1, 1]), (sc.scalar(0, d), [2, 2, 2]), (sc.scalar(4, d), [])]
                valid = copy.deepcopy(s)
                valid['coefficient'].update(kind=0, selectors=[None]*3, axes=[], source_id=None, values=[], width=None)
                mask = boolean_table(valid)
                tables = [[tuple((a+1)*(i+2)*(j+3) for j in range(d)) if mask[i] != sc.scalar(0,d) else sc.scalar(0,d)
                           for i in range(32)] for a in range(3)]
                claim(s, tables)
                yield s, tables
        for bits, inputs, mode in ((0, 0, 0), (0, 1, 1), (2, 0, 1), (2, 1, 2)):
            s = fixture(d)
            s.update(layout=[(bits, 1 << bits)], inputs=[41]*inputs)
            s['coefficient'].update(selectors=[None])
            s['terms'] = [] if mode == 0 else [(sc.scalar(3 if mode == 1 else 0, d), [] if mode == 1 else [0,0,0])]
            tables = [[sc.scalar(i+2,d) for i in range(1 << bits)] for _ in s['inputs']]
            claim(s, tables)
            yield s, tables


def corpus():
    inputs, expected = [], []
    for s, tables in cases():
        t = Transcript(PUBLIC, s['field'])
        t.absorb(SOURCES, sources(s, tables))
        proof = stage.prove(t, s, tables)
        honest = outcome(s, tables, proof)
        assert honest['decision'] == 'accept' and honest['continuation'] == t.challenge()[0].hex()
        variants = [proof]
        if proof['rounds']:
            short = copy.deepcopy(proof); short['rounds'].pop(); variants.append(short)
            bad = copy.deepcopy(proof); bad['rounds'][0][0] = sc.add(bad['rounds'][0][0], sc.scalar(1,s['field'])); variants.append(bad)
        if len(s['inputs']) == 3:
            unused = copy.deepcopy(proof); unused['final'][0] = sc.add(unused['final'][0], sc.scalar(1,s['field'])); variants.append(unused)
        if not s['terms'] or all(c == sc.scalar(0,s['field']) for c,_ in s['terms']):
            coefficient = copy.deepcopy(proof); coefficient['final'][-1] = sc.add(coefficient['final'][-1],sc.scalar(1,s['field'])); variants.append(coefficient)
        for candidate in variants:
            inputs.append(dict(statement=s,tables=tables,proof=candidate))
            expected.append(outcome(s,tables,candidate))
    return inputs, expected


def main():
    assert sys.argv[1:] in ([], ['--write-digest'])
    inputs, expected = corpus()
    raw = ''.join(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n' for row in expected).encode()
    digest = hashlib.sha256(raw).hexdigest()+'\n'
    path = ROOT/'tests/negative-controls/fixtures/stacked-public.sha256'
    if sys.argv[1:] == ['--write-digest']:
        with path.open('x') as output:
            output.write(digest)
    assert path.read_text() == digest, 'independent stacked wire digest drift'
    result = subprocess.run(['cargo','run','--quiet','-p','stele-negative-controls','--example','stacked_corpus','--locked','--offline'],
                            cwd=ROOT, input=''.join(json.dumps(row)+'\n' for row in inputs), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    actual = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(actual) == len(expected), (len(actual), len(expected))
    for index, (a,b) in enumerate(zip(actual,expected)):
        assert a == b, (index,a,b)
    print(f'stacked native wire: {len(inputs)} both-field decisions; complete frames/proofs/restored claims/SC/continuation agree; {digest.strip()}')


if __name__ == '__main__':
    main()
