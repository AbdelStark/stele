"""RFC-0024 ordered A5 import/consumption over the unchanged Python engines.

Reuse the historical parser and geometry. Keep this operation's import schedule
separate so an early failure never executes or hides a later range verification.
"""
import struct
from lookup_reference import make


class Lookup:
    def __init__(self, oracle):
        self.o = oracle
        historical = make(oracle)
        self.geometry, self.parse = historical.geometry, historical.parse
        self.size, self.opening_record = historical.size, historical.opening_record

    @staticmethod
    def wrapped(kind, call, *args):
        try:
            return call(*args)
        except ValueError as error:
            name = str(error)
            if kind == 'Pcs':
                assert name in ('ProofShape', 'NoncanonicalField', 'ValueMismatch', 'ColumnMismatch', 'RootMismatch'), name
                name = 'Merkle(RootMismatch)' if name == 'RootMismatch' else name
            else:
                assert name in ('NoncanonicalField', 'RootMismatch', 'Pole', 'SelectorMismatch', 'CoefficientMismatch', 'RoundSumMismatch', 'FinalEvaluationMismatch'), name
                if name in ('RoundSumMismatch', 'FinalEvaluationMismatch'):
                    name = f'Sumcheck({name})'
            raise ValueError(f'{kind}({name})') from error

    def register(self, case, geometry):
        o, pcs = self.o, self.o.pcs
        out = dict(phase='import', registrations=[None, None], _retained_mu_handles=[])
        cap = sum(len(b'stele/v0.1/pcs-certificate/public')+105+self.size(s, 0)-1 for s in geometry['mu'])
        try:
            pcs.require(cap <= case.get('import_cap', cap), 'ResourceLimit')
            packets, _ = self.parse(case, geometry, bytes.fromhex(case['proof']))
            for j, (source, certificate, _) in enumerate(packets):
                local, before = o.hashes(), len(o.CREATED)
                try:
                    with o.local_hashes(local):
                        owner = self.wrapped('Pcs', pcs.verify_certificate, source, certificate)
                        out['_retained_mu_handles'].append(owner)
                finally:
                    assert len(o.CREATED) == before+1
                    out['registrations'][j] = dict(transcript=o.CREATED[-1].usage.copy(), non_transcript=local)
        except ValueError as error:
            out['decision'] = str(error)
        else:
            out['decision'] = 'accept'
        return out

    def tree_record(self, transcript, statement, proof):
        ft, sc = self.o.ft, self.o.sc
        before = transcript.draws.copy()
        result = self.wrapped('Fraction', ft.verify, transcript, statement, proof)
        record = dict(point=[sc.encode(v).hex() for v in result['point']],
            claims=[[i, sc.encode(v).hex()] for i, v in zip(result['ids'], result['values'], strict=True)],
            accounting=dict(tree_id=statement['id'], field_degree=transcript.degree,
                gamma=transcript.draws.get(ft.GAMMA, 0)-before.get(ft.GAMMA, 0),
                fold=transcript.draws.get(ft.FOLD, 0)-before.get(ft.FOLD, 0), layers=result['sc']))
        return result, record

    def consume(self, case, geometry, transcript, imported):
        """Only the closed operation supplies this genuinely imported owner roster."""
        o = self.o
        pcs, ft, sc, ti = o.pcs, o.ft, o.sc, o.ti
        pcs.require(imported['phase'] == 'import' and imported['decision'] == 'accept', 'ImportedRoster')
        handles = imported['_retained_mu_handles']
        pcs.require(len(handles) == len(geometry['mu']), 'ImportedRoster')
        d, m, b, identity = (case[k] for k in ('degree', 'm', 'b', 'lookup_id'))
        one = sc.scalar(1, d)
        out = dict(imported, phase='outer')
        local = o.hashes()
        try:
            with o.local_hashes(local):
                packets, reps = self.parse(case, geometry, bytes.fromhex(case['proof']))
                pcs.require(all(s.bytes() == h.source.bytes() for (s, _, _), h in zip(packets, handles, strict=True)), 'CertificateContext')
                for (source, raw, _), handle in zip(packets, handles, strict=True):
                    public = source.bytes()
                    identity_hash = pcs.blake3(b'stele/v0.1/pcs-certificate/id'+struct.pack('<Q', len(public))+public+struct.pack('<Q', len(raw))+raw).digest()
                    pcs.require(identity_hash == handle.identity, 'CertificateIdentity')
                transcript.absorb(o.STATEMENT, o.statements(case, geometry['desc'], geometry['originals']))
                theta = []
                for j in range(len(handles)):
                    transcript.absorb(o.UNITS, struct.pack('<QB', identity, j))
                    theta.append([transcript.field(o.UNIT) for _ in range(m-b)])
                transcript.absorb(o.MULTIPLICITIES, struct.pack('<QB', identity, len(handles))+
                    b''.join(bytes([j])+h.source.bytes()+h.identity for j, h in enumerate(handles)))
                pairs = []
                for j in range(len(handles)):
                    transcript.absorb(o.REPETITION, struct.pack('<QBB', identity, j, 0))
                    pairs.append((transcript.field(o.BETA), transcript.field(o.ALPHA)))
                records = []
                rows = ti.canonical_rows(geometry['desc'])
                for j, (packet, (beta, alpha)) in enumerate(zip(reps, pairs, strict=True)):
                    transcript.absorb(o.REPETITION, struct.pack('<QBB', identity, j, 1))
                    left = dict(id=4*identity+2*j, m=m, b=b, leaves=(8*identity+4*j, 8*identity+4*j+1), theta=theta[j])
                    k = geometry['n'].bit_length()-1
                    right = dict(id=left['id']+1, m=k, b=k, leaves=(left['leaves'][0]+2, left['leaves'][0]+3), theta=[])
                    lr, lrecord = self.tree_record(transcript, left, packet['left'])
                    rr, rrecord = self.tree_record(transcript, right, packet['right'])
                    self.wrapped('Fraction', ft.root_equation, packet['left']['root'], packet['right']['root'], d)
                    columns = [ft.mle([sc.scalar(row[a], d) for row in rows], rr['point'], d) for a in range(geometry['c'])]
                    valid = ft.mle([one]*geometry['real']+[sc.scalar(0, d)]*(geometry['n']-geometry['real']), rr['point'], d)
                    expected = sc.add(sc.add(one, sc.mul(sc.add(alpha, sc.neg(one)), valid)), sc.neg(pcs.dot(ft.powers(beta, geometry['c'], d), columns, d)))
                    pcs.require(rr['values'][1] == expected, 'TableDenominatorMismatch')
                    selected = self.wrapped('Fraction', ft.verify_leaf, transcript, left, lr,
                        [sc.scalar(v, d) for v in case['selector']], [h.source.identity for h in geometry['originals']],
                        packet['selected'], alpha, beta)
                    originals = []
                    for h, (oid, value), (proof, _) in zip(geometry['originals'], selected['claims'], packet['originals'], strict=True):
                        point = selected['point']
                        self.wrapped('Pcs', pcs.verify_opening, transcript, oid, h, pcs.eq(point[:h.source.ell], d),
                                     pcs.eq(point[h.source.ell:], d), value, proof)
                        originals.append(self.opening_record(h, oid))
                    pcs.require(pcs.dot([one]*len(packet['values']), packet['values'], d) == rr['values'][0], 'PieceSumMismatch')
                    # RFC-0024 fixes complete range8 multiplicities, ell=0, one full packed piece.
                    source = handles[j].source
                    pcs.require(source.ell == 0 and geometry['real'] == geometry['n'] == 256
                                and 1 << source.m == 256*d and len(packet['values']) == 1, 'MultiplicityGeometry')
                    basis = [tuple(int(i == k) for i in range(d)) for k in range(d)]
                    coef = [sc.mul(w, e) for w in pcs.eq(rr['point'], d) for e in basis]
                    transcript.absorb(o.CLAIMS, struct.pack('<QBB', identity, j, 1)+pcs.field_bytes([*rr['point'], rr['values'][0]])
                        +b'\0'+sc.encode(packet['values'][0]))
                    self.wrapped('Pcs', pcs.verify_opening, transcript, 0, handles[j], [one], coef,
                                 packet['values'][0], packet['openings'][0][0])
                    records.append(dict(lookup=lrecord, table=rrecord, selected=dict(tree_id=left['id'],
                        point=[sc.encode(v).hex() for v in selected['point']],
                        claims=[[i, sc.encode(v).hex()] for i, v in selected['claims']], sc=selected['sc']),
                        originals=originals, multiplicities=[self.opening_record(handles[j], 0)]))
        except ValueError as error:
            out['decision'] = str(error)
        else:
            out.update(decision='accept', record=dict(parameters=dict(id=identity, degree=d, positions=1 << m,
                table_rows=geometry['real'], columns=geometry['c'], group_bits=b, unit_bits=m-b, repetitions=len(handles),
                identity_numerator=m-b+(1 << m)+geometry['c']*geometry['real']-1), repetitions=records))
        out['usage'] = dict(transcript=transcript.usage.copy(), non_transcript=local)
        return out

