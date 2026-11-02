"""Source-qualified A5 orchestration adapters; unchanged component engines.

Derived mechanically from lookup_corpus.reference and lookup_closed.batch.
Changes: caller transcript and supplied original handles; no producer or diagnostic
continuation; expose the actual parser/consumer and import timers. The verifier
retains every original check and rejection path.
"""
import struct
from types import SimpleNamespace
from time import perf_counter_ns


def make(o):
    pcs, ft, sc, ti = o.pcs, o.ft, o.sc, o.ti
    require = pcs.require
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

    def size(s, kind):
        return 1+4*s.degree*(1 << s.m)+pcs.counts(s.m, s.blowup)[kind]*(s.tree().width+32*s.tree().height())

    def pieces(s, real):
        q, tail = divmod(real, (1 << s.m)//s.degree)
        return [i for i, present in ((0, q > 0), (1, tail > 0)) if present]

    def parse(case, g, wire):
        d, m, k = case['degree'], case['m'], g['n'].bit_length()-1
        tree_size = lambda v: 4*d*(2+2*v*v+3*v)
        length = 2+sum(32+size(s, 0) for s in g['mu'])+sum(
            tree_size(m)+tree_size(k)+4*d*(4*m+g['c']+2)+sum(size(h.source, 1) for h in g['originals'])
            +len(pieces(s, g['real']))*(4*d+size(s, 1)) for s in g['mu'])
        require(len(wire) == length and wire[:2] == bytes([1, d]), 'ProofShape')
        offset, packets, reps = 2, [], []

        def take(count):
            nonlocal offset
            start = offset
            offset += count
            return wire[start:offset], start

        def fields(count, kind='Fraction'):
            raw, start = take(4*d*count)
            if kind == 'piece':
                try:
                    return pcs.fields(raw, d), start
                except ValueError as error:
                    raise ValueError('ProofShape') from error
            return wrapped(kind, pcs.fields, raw, d), start

        def tree(v):
            root, start = fields(2)
            steps = []
            for level in range(v):
                rounds = [fields(4)[0] for _ in range(level)]
                steps.append(dict(rounds=rounds, final=fields(5)[0]))
            return dict(root=tuple(root), steps=steps), start

        def opening(s):
            raw, start = take(size(s, 1))
            wrapped('Pcs', pcs.parse, s, raw, pcs.counts(s.m, s.blowup)[1])
            return raw, start

        for s in g['mu']:
            root, _ = take(32)
            raw, start = take(size(s, 0))
            wrapped('Pcs', pcs.parse, s, raw, pcs.counts(s.m, s.blowup)[0])
            packets.append((pcs.Source(d, s.identity, s.ell, s.m, s.blowup, root), raw, start))
        for s in g['mu']:
            left, left_start = tree(m)
            right, _ = tree(k)
            selected = dict(rounds=[fields(4)[0] for _ in range(m)], final=fields(g['c']+2)[0])
            originals = [opening(h.source) for h in g['originals']]
            values, start = fields(len(pieces(s, g['real'])), 'piece')
            reps.append(dict(left=left, right=right, left_start=left_start, selected=selected,
                originals=originals, values=values, value_start=start, openings=[opening(s) for _ in values]))
        assert offset == len(wire)
        return packets, reps

    def coefficients(s, point, real):
        zero = sc.scalar(0, s.degree)
        q, tail = divmod(real, (1 << s.m)//s.degree)
        rw, cw = pcs.eq(point[:s.ell], s.degree), pcs.eq(point[s.ell:], s.degree)
        basis = [tuple(int(i == j) for i in range(s.degree)) for j in range(s.degree)]
        return [(i, [w if (u < q if i == 0 else u == q) else zero for u, w in enumerate(rw)],
            [sc.mul(w, e) if i == 0 or v < tail else zero for v, w in enumerate(cw) for e in basis]) for i in pieces(s, real)]

    def opening_record(handle, identity):
        s = handle.source
        length = 1 << (s.m+s.blowup)
        distance = length if s.m == 0 else length-(1 << s.m)
        qc, qo = pcs.counts(s.m, s.blowup)
        return dict(id=identity, queries=qo, kind='Opening', certificate=dict(
            id=handle.identity.hex(), source=s.bytes().hex(), ell=s.ell, degree=s.degree,
            kind='Certificate', length=length, distance=distance, radius=(distance-1)//3,
            certificate_queries=qc, opening_queries=qo))

    def tree_record(t, s, proof):
        before = t.draws.copy()
        result = wrapped('Fraction', ft.verify, t, s, proof)
        record = dict(point=[sc.encode(v).hex() for v in result['point']],
            claims=[[i, sc.encode(v).hex()] for i, v in zip(result['ids'], result['values'])],
            accounting=dict(tree_id=s['id'], field_degree=t.degree,
                gamma=t.draws.get(ft.GAMMA, 0)-before.get(ft.GAMMA, 0),
                fold=t.draws.get(ft.FOLD, 0)-before.get(ft.FOLD, 0), layers=result['sc']))
        return result, record

    def verify(case, g, t):
        d, m, b, identity = (case[k] for k in ('degree', 'm', 'b', 'lookup_id'))
        zero, one = sc.scalar(0, d), sc.scalar(1, d)
        out = dict(name=case['name'], degree=d, originals=g['setup'], phase='import', registrations=[None, None], registration_ns=[0, 0])
        handles = []
        cap = sum(len(b'stele/v0.1/pcs-certificate/public')+105+size(s, 0)-1 for s in g['mu'])
        try:
            require(cap <= case.get('import_cap', cap), 'ResourceLimit')
            packets, _ = parse(case, g, bytes.fromhex(case.get('registration_proof', case['proof'])))
            for j, (source, certificate, _) in enumerate(packets):
                local, before = o.hashes(), len(o.CREATED)
                start_ns = perf_counter_ns()
                try:
                    with o.local_hashes(local):
                        handles.append(wrapped('Pcs', pcs.verify_certificate, source, certificate))
                finally:
                    out['registration_ns'][j] = perf_counter_ns()-start_ns
                    assert len(o.CREATED) == before+1
                    out['registrations'][j] = dict(transcript=o.CREATED[-1].usage.copy(), non_transcript=local)
        except ValueError as error:
            out['decision'] = str(error)
            out['_retained_mu_handles'] = handles
            return out
        out['phase'] = 'outer'
        local = o.hashes()
        try:
            with o.local_hashes(local):
                packets, reps = parse(case, g, bytes.fromhex(case['proof']))
                require(all(s.bytes() == h.source.bytes() for (s, _, _), h in zip(packets, handles)), 'CertificateContext')
                for (source, raw, _), handle in zip(packets, handles):
                    public = source.bytes()
                    hashed = pcs.blake3(b'stele/v0.1/pcs-certificate/id'+struct.pack('<Q', len(public))+public+struct.pack('<Q', len(raw))+raw).digest()
                    require(hashed == handle.identity, 'CertificateIdentity')
                t.absorb(o.STATEMENT, o.statements(case, g['desc'], g['originals']))
                theta = []
                for j in range(len(handles)):
                    t.absorb(o.UNITS, struct.pack('<QB', identity, j))
                    theta.append([t.field(o.UNIT) for _ in range(m-b)])
                t.absorb(o.MULTIPLICITIES, struct.pack('<QB', identity, len(handles))+
                    b''.join(bytes([j])+h.source.bytes()+h.identity for j, h in enumerate(handles)))
                pairs = []
                for j in range(len(handles)):
                    t.absorb(o.REPETITION, struct.pack('<QBB', identity, j, 0))
                    pairs.append((t.field(o.BETA), t.field(o.ALPHA)))
                records = []
                rows = ti.canonical_rows(g['desc'])
                for j, (packet, (beta, alpha)) in enumerate(zip(reps, pairs)):
                    t.absorb(o.REPETITION, struct.pack('<QBB', identity, j, 1))
                    left = dict(id=4*identity+2*j, m=m, b=b, leaves=(8*identity+4*j, 8*identity+4*j+1), theta=theta[j])
                    k = g['n'].bit_length()-1
                    right = dict(id=left['id']+1, m=k, b=k, leaves=(left['leaves'][0]+2, left['leaves'][0]+3), theta=[])
                    lr, lrecord = tree_record(t, left, packet['left'])
                    rr, rrecord = tree_record(t, right, packet['right'])
                    wrapped('Fraction', ft.root_equation, packet['left']['root'], packet['right']['root'], d)
                    columns = [ft.mle([sc.scalar(row[a], d) for row in rows], rr['point'], d) for a in range(g['c'])]
                    valid = ft.mle([one]*g['real']+[zero]*(g['n']-g['real']), rr['point'], d)
                    expected = sc.add(sc.add(one, sc.mul(sc.add(alpha, sc.neg(one)), valid)), sc.neg(pcs.dot(ft.powers(beta, g['c'], d), columns, d)))
                    require(rr['values'][1] == expected, 'TableDenominatorMismatch')
                    selected = wrapped('Fraction', ft.verify_leaf, t, left, lr, [sc.scalar(v, d) for v in case['selector']],
                        [h.source.identity for h in g['originals']], packet['selected'], alpha, beta)
                    originals = []
                    for h, (oid, value), (proof, _) in zip(g['originals'], selected['claims'], packet['originals']):
                        p = selected['point']
                        wrapped('Pcs', pcs.verify_opening, t, oid, h, pcs.eq(p[:h.source.ell], d), pcs.eq(p[h.source.ell:], d), value, proof)
                        originals.append(opening_record(h, oid))
                    require(pcs.dot([one]*len(packet['values']), packet['values'], d) == rr['values'][0], 'PieceSumMismatch')
                    coefs = coefficients(handles[j].source, rr['point'], g['real'])
                    t.absorb(o.CLAIMS, struct.pack('<QBB', identity, j, len(coefs))+pcs.field_bytes([*rr['point'], rr['values'][0]])+
                        b''.join(bytes([piece])+sc.encode(value) for (piece, _, _), value in zip(coefs, packet['values'])))
                    opened = []
                    for (piece, a, coef), value, (proof, _) in zip(coefs, packet['values'], packet['openings']):
                        wrapped('Pcs', pcs.verify_opening, t, piece, handles[j], a, coef, value, proof)
                        opened.append(opening_record(handles[j], piece))
                    records.append(dict(lookup=lrecord, table=rrecord, selected=dict(tree_id=left['id'],
                        point=[sc.encode(v).hex() for v in selected['point']],
                        claims=[[i, sc.encode(v).hex()] for i, v in selected['claims']], sc=selected['sc']),
                        originals=originals, multiplicities=opened))
        except ValueError as error:
            out['decision'] = str(error)
        else:
            out.update(decision='accept', record=dict(parameters=dict(id=identity, degree=d, positions=1 << m,
                table_rows=g['real'], columns=g['c'], group_bits=b, unit_bits=m-b, repetitions=len(handles),
                identity_numerator=m-b+(1 << m)+g['c']*g['real']-1), repetitions=records))
        out['usage'] = dict(transcript=t.usage.copy(), non_transcript=local)
        out['_retained_mu_handles'] = handles
        return out

    def geometry(case, handles):
        info, d = case['table'], case['degree']
        desc = ti.Descriptor(info['name'], info['version'], bytes.fromhex(info['params_hex']))
        real, n, c = ti.shape(desc)
        mu = [pcs.Source(d, v['id'], v['ell'], (n*d).bit_length()-1-v['ell'],
                         v['blowup'], bytes(32)) for v in case['multiplicities']]
        return dict(desc=desc, real=real, n=n, c=c, originals=handles, mu=mu, setup=[])

    def proof_size(case, g):
        d, m, k = case['degree'], case['m'], g['n'].bit_length()-1
        tree_size = lambda v: 4*d*(2+2*v*v+3*v)
        return 2+sum(32+size(s, 0) for s in g['mu'])+sum(
            tree_size(m)+tree_size(k)+4*d*(4*m+g['c']+2)
            +sum(size(h.source, 1) for h in g['originals'])
            +len(pieces(s, g['real']))*(4*d+size(s, 1)) for s in g['mu'])

    return SimpleNamespace(verify=verify, parse=parse,
                           geometry=geometry, size=size, proof_size=proof_size,
                           opening_record=opening_record)
