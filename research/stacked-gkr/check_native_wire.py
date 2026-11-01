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
sys.path.insert(0, str(ROOT/'research/merkle-oracle'))
import field_wire as pcs
assert pcs.sc is sc and Path(pcs.__file__).resolve() == ROOT/'research/merkle-oracle/field_wire.py'
CERTIFIED_PUBLIC = b'certified stacked wire oracle'


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


def hash_usage():
    return dict(hash_evaluations=0, xof_requests=0, xof_bytes=0,
                state_updates=0, candidate_words=0, column_attempts=0)


class CertifiedTranscript(pcs.Transcript):
    """Observe actual calls; the inherited transcript still derives every draw."""
    def __init__(self, degree):
        super().__init__(CERTIFIED_PUBLIC, degree)
        self.usage = hash_usage() | dict(hash_evaluations=2, state_updates=1)
        self.draws, self.completed_columns, self.in_column = [], 0, False

    def absorb(self, label, payload):
        if label in (SOURCES, stage.STACK):
            self.state = blake3(pcs.frame(self.state, 0, label, payload)).digest()
        else:
            super().absorb(label, payload)
        self.usage['hash_evaluations'] += 1
        self.usage['state_updates'] += 1

    def challenge(self, label=pcs.CHALLENGE):
        # These bounded fixtures exercise successful inner samples. No failed
        # producer/sample accounting is inferred from this reference helper.
        value, consumed = super().challenge(label)
        self.usage['xof_requests'] += 1
        self.usage['xof_bytes'] += 256
        self.usage['candidate_words'] += consumed
        self.usage['hash_evaluations'] += 1
        self.usage['state_updates'] += 1
        if label == pcs.CHALLENGE:
            self.draws.append(struct.unpack('<'+'I'*self.degree, value))
        return value, consumed

    def field(self, label):
        if self.in_column:
            self.usage['column_attempts'] += 1
        return super().field(label)

    def column(self, label, size):
        self.in_column = True
        try:
            index = super().column(label, size)
        finally:
            self.in_column = False
        self.completed_columns += 1
        return index


def pcs_error(error):
    name = str(error)
    return 'Merkle(RootMismatch)' if name == 'RootMismatch' else name


def certified_sources(s, certificates):
    return struct.pack('<BBQI', 1, 1, s['id'], len(certificates))+b''.join(
        c.source.bytes()+c.identity for c in certificates)


def certified_preflight(s, certificates, proof, openings):
    try:
        encode(s)
        source = s['coefficient']['source_id']
        need(source is None or source not in [s['output']['id'], s['coefficient_id'], *s['inputs']])
    except ValueError:
        raise ValueError('Stacked(InvalidStacked)') from None
    i, d = stage.instance(s), s['field']
    pcs.require(len(certificates) == len(s['inputs']) == len(openings)
                and all(real == 1 << bits for bits, real in s['layout'])
                and all(c.source.identity == identity and c.source.degree == d
                        and c.source.ell+c.source.m == i['m']
                        for c, identity in zip(certificates, s['inputs'])), 'SourceRoster')
    sc.validate(i, d)
    pcs.require(len(proof['rounds']) == i['m'] and len(proof['final']) == len(i['ids'])
                and all(len(row) == sc.degree(i)+1 for row in proof['rounds']),
                'Stacked(Sumcheck(ProofShape))')
    for value in [x for row in proof['rounds'] for x in row]+proof['final']:
        field(value, d)
    for c, opening in zip(certificates, openings):
        try:
            pcs.parse(c.source, opening, pcs.counts(c.source.m, c.source.blowup)[1])
        except ValueError as error:
            raise ValueError('Pcs('+pcs_error(error)+')') from None


def certificate_record(c):
    source = c.source
    length = 1 << (source.m+source.blowup)
    distance = length if source.m == 0 else length-(1 << source.m)  # A9 §2.
    qc, qo = pcs.counts(source.m, source.blowup)
    return dict(id=c.identity.hex(), source=source.bytes().hex(), ell=source.ell,
                degree=source.degree, kind='Certificate', length=length, distance=distance,
                radius=(distance-1)//3, certificate_queries=qc, opening_queries=qo)


def certified_outcome(case):
    s, proof = case['statement'], case['proof']
    certificates = []
    for info in case['certificates']:
        source = pcs.Source(s['field'], info['id'], info['ell'], info['m'], info['blowup'], bytes.fromhex(info['root']))
        assert source.bytes().hex() == info['bytes']
        try:
            c = pcs.verify_certificate(source, bytes.fromhex(info['certificate']))
        except ValueError as error:
            return dict(phase='registration', decision=pcs_error(error))
        assert c.identity.hex() == info['certificate_id']
        certificates.append(c)
    openings = list(map(bytes.fromhex, case['openings']))
    t, hashes = CertifiedTranscript(s['field']), 0
    try:
        certified_preflight(s, certificates, proof, openings)
        t.absorb(SOURCES, certified_sources(s, certificates))
        try:
            reduction = stage.verify_reduction(t, s, proof)
        except ValueError as error:
            name = str(error)
            if name in ('ProofShape', 'RoundSumMismatch', 'FinalEvaluationMismatch'):
                name = 'Sumcheck('+name+')'
            raise ValueError('Stacked('+name+')') from None
        for c, (identity, value), opening in zip(certificates, reduction['claims'], openings):
            split = c.source.ell
            a, b = pcs.eq(reduction['point'][:split], s['field']), pcs.eq(reduction['point'][split:], s['field'])
            before = t.completed_columns
            try:
                pcs.verify_opening(t, identity, c, a, b, value, opening)
            except ValueError as error:
                raise ValueError('Pcs('+pcs_error(error)+')') from None
            finally:
                # Every returned index in these fixed-shape fixtures reaches one
                # complete Merkle path, including a path ending in RootMismatch.
                hashes += (t.completed_columns-before)*(1+c.source.tree().height())
    except ValueError as error:
        return dict(phase='stage', decision=str(error), usage=dict(
            transcript=t.usage.copy(), non_transcript=hash_usage() | dict(hash_evaluations=hashes)))
    i, d = stage.instance(s), s['field']
    observed = dict(transcript=t.usage.copy(), non_transcript=hash_usage() | dict(hash_evaluations=hashes))
    return dict(phase='stage', decision='accept', stack=encode(s).hex(),
        sources=certified_sources(s, certificates).hex(), instance=sc.instance_bytes(i, d).hex(),
        proof=[sc.message(i, r, row).hex() for r, row in enumerate(proof['rounds'])]
              +[sc.message(i, len(i['ids']), proof['final']).hex()], openings=case['openings'],
        registrations=[info['certificate'] for info in case['certificates']],
        point=[field(x, d).hex() for x in reduction['point']],
        claims=[[identity, field(x, d).hex()] for identity, x in reduction['claims']], sc=reduction['sc'],
        records=[dict(id=identity, queries=pcs.counts(c.source.m,c.source.blowup)[1], kind='Opening',
                      certificate=certificate_record(c)) for identity,c in zip(s['inputs'],certificates)],
        usage=observed, producer_usage=dict(transcript=t.usage.copy(),non_transcript=hash_usage()),
        continuation=t.challenge()[0].hex())


def source_fixture(d, identity, ell, m, matrix):
    source, witness = pcs.commit(matrix, ell, m, 1, d, identity)
    proof = pcs.certify(source, witness)
    verified = pcs.verify_certificate(source, proof)
    info = dict(id=identity,ell=ell,m=m,blowup=1,root=source.root.hex(),bytes=source.bytes().hex(),
                certificate=proof.hex(),certificate_id=verified.identity.hex(),matrix=matrix)
    return info, verified, witness


def certified_case(s):
    d, m = s['field'], sum(bits for bits,_ in s['layout'])
    infos, certificates, witnesses, tables = [], [], [], []
    for ordinal, identity in enumerate(s['inputs']):
        row_bits = ordinal % (m+1)
        values = ([0] if m == 0 else [i >> (m-1) for i in range(1 << m)]) if ordinal == 0 else [i+ordinal+2 for i in range(1 << m)]
        width = 1 << (m-row_bits)
        matrix = [values[j:j+width] for j in range(0,len(values),width)]
        info, c, witness = source_fixture(d,identity,row_bits,m-row_bits,matrix)
        infos.append(info); certificates.append(c); witnesses.append(witness)
        tables.append([sc.scalar(x,d) for x in values])
    claim(s, tables)
    t = CertifiedTranscript(d)
    t.absorb(SOURCES,certified_sources(s,certificates))
    proof = stage.prove(t,s,tables)
    assert len(t.draws) == m
    point = [None]*m
    for axis, value in zip(stage.permutation(s),t.draws):
        point[axis] = value
    openings = []
    for identity,c,witness,value in zip(s['inputs'],certificates,witnesses,proof['final']):
        split = c.source.ell
        openings.append(pcs.open_functional(t,identity,c,witness,
            pcs.eq(point[:split],d),pcs.eq(point[split:],d),value).hex())
    result = dict(mode='certified',statement=s,certificates=infos,proof=proof,openings=openings)
    expected = certified_outcome(result)
    assert expected['decision'] == 'accept'
    assert expected['point'] == [field(x,d).hex() for x in point]
    assert expected['producer_usage'] == dict(transcript=t.usage.copy(),non_transcript=hash_usage())
    assert expected['continuation'] == t.challenge()[0].hex()
    return result, expected


def certified_corpus():
    inputs, expected = [], []
    for d in (4,8):
        specifications = []
        for order in (0,1):
            for kind in (0,3):
                s = fixture(d,kind,order)
                s['layout'] = [(1,2),(1,2)]
                s['coefficient']['selectors'] = [None,None]
                if kind == 3:
                    s['coefficient'].update(axes=[0,1],values=[0,1])
                    s['inputs'] = s['inputs'][:2]
                s['terms'] = [] if kind == 3 else [(sc.scalar(3,d),[1,1,1]),(sc.scalar(0,d),[2,2,2])]
                specifications.append(s)
        for count in (1,0):
            s = fixture(d,order=1)
            s.update(layout=[(0,1)] if count else [(1,2),(1,2)],inputs=[14] if count else [],
                     terms=[] if count else [(sc.scalar(3,d),[])])
            s['coefficient']['selectors'] = [None]*len(s['layout'])
            specifications.append(s)
        for s in specifications:
            case, honest = certified_case(s)
            inputs.append(case); expected.append(honest)
            variants = []
            if len(s['inputs']) == 3 and s['order'] == 1:
                for change in (
                    lambda c: c['proof']['rounds'].pop(),
                    lambda c: c['proof']['rounds'][0].clear(),
                    lambda c: c['proof']['final'].pop(),
                    lambda c: c['openings'].pop(),
                    lambda c: c['openings'].append(c['openings'][0]),
                    lambda c: c['certificates'].reverse(),
                    lambda c: c['statement']['layout'].__setitem__(0,(1,1)),
                ):
                    bad=copy.deepcopy(case); change(bad); variants.append(bad)
                for region in ('short','suffix','version','field','path'):
                    bad=copy.deepcopy(case); raw=bytearray.fromhex(bad['openings'][1])
                    if region == 'short': raw.pop()
                    elif region == 'suffix': raw.append(0)
                    elif region == 'version': raw[0]=2
                    elif region == 'field': raw[1:5]=struct.pack('<I',sc.P)
                    else: raw[1+4*d*(1 << bad['certificates'][1]['m'])] ^= 1
                    bad['openings'][1]=raw.hex(); variants.append(bad)
                bad=copy.deepcopy(case)
                bad['proof']['rounds'][0][0]=sc.add(bad['proof']['rounds'][0][0],sc.scalar(1,d)); variants.append(bad)
                bad=copy.deepcopy(case)
                # f_0=x_layer; the raw point's first coordinate is canonical x_inner.
                wrong=struct.unpack('<'+'I'*d,bytes.fromhex(honest['point'][1]))
                assert wrong != bad['proof']['final'][0]
                bad['proof']['final'][0]=wrong; variants.append(bad)
                bad=copy.deepcopy(case)
                bad['certificates'][0]=source_fixture(d,s['inputs'][0],0,1,[[0,1]])[0]; variants.append(bad)
                bad=copy.deepcopy(case)
                raw=bytearray.fromhex(bad['certificates'][0]['certificate'])
                raw[1+4*d*(1 << bad['certificates'][0]['m'])] ^= 1
                bad['certificates'][0]['certificate']=raw.hex(); variants.append(bad)
            if s['coefficient']['kind'] == 3 and s['order'] == 1:
                bad=copy.deepcopy(case)
                bad['proof']['final'][-1]=sc.add(bad['proof']['final'][-1],sc.scalar(1,d)); variants.append(bad)
            if len(s['inputs']) == 1 and s['layout'] == [(0,1)]:
                bad=copy.deepcopy(case)
                bad['certificates'][0]=source_fixture(d,s['inputs'][0],0,0,[[1]])[0]; variants.append(bad)
            for candidate in variants:
                result=certified_outcome(candidate)
                assert result['decision'] != 'accept'
                inputs.append(candidate); expected.append(result)
    return inputs, expected


def main():
    assert sys.argv[1:] in ([], ['--write-digest'], ['--write-certified-digest'])
    inputs, expected = corpus()
    raw = ''.join(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n' for row in expected).encode()
    digest = hashlib.sha256(raw).hexdigest()+'\n'
    path = ROOT/'tests/negative-controls/fixtures/stacked-public.sha256'
    if sys.argv[1:] == ['--write-digest']:
        with path.open('x') as output:
            output.write(digest)
    assert path.read_text() == digest, 'independent stacked wire digest drift'
    public_count = len(inputs)
    certified_inputs, certified_expected = certified_corpus()
    certified_raw = ''.join(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n' for row in certified_expected).encode()
    certified_digest = hashlib.sha256(certified_raw).hexdigest()+'\n'
    certified_path = ROOT/'tests/negative-controls/fixtures/stacked-certified.sha256'
    if sys.argv[1:] != ['--write-certified-digest']:
        assert certified_path.read_text() == certified_digest, 'independent certified stacked digest drift'
    inputs += certified_inputs; expected += certified_expected
    result = subprocess.run(['cargo','run','--quiet','-p','stele-negative-controls','--example','stacked_corpus','--locked','--offline'],
                            cwd=ROOT, input=''.join(json.dumps(row)+'\n' for row in inputs), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    actual = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(actual) == len(expected), (len(actual), len(expected))
    for index, (a,b) in enumerate(zip(actual,expected)):
        assert a == b, (index,{k:(str(a.get(k))[:1000],str(b.get(k))[:1000])
                              for k in a.keys()|b.keys() if a.get(k) != b.get(k)})
    if sys.argv[1:] == ['--write-certified-digest']:
        with certified_path.open('x') as output:
            output.write(certified_digest)
    print(f'stacked native wire: {public_count} both-field decisions; complete frames/proofs/restored claims/SC/continuation agree; {digest.strip()}')
    print(f'stacked certified wire: {len(certified_inputs)} both-field decisions; actual certificates/producer/openings/records/usage/continuation agree; {certified_digest.strip()}')


if __name__ == '__main__':
    main()
