"""RFC-0008 A5: compose unchanged reference consumers; never native-derived authority."""
import copy
import struct


def batch(o, inputs, produced):
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

    def geometry(case, output):
        d, m = case['degree'], case['m']
        info = case['table']
        desc = ti.Descriptor(info['name'], info['version'], bytes.fromhex(info['params_hex']))
        real, n, c = ti.shape(desc)
        originals = []
        for info, cert in zip(case['originals'], output['originals']):
            source = pcs.Source(d, info['id'], info['ell'], m-info['ell'], info['blowup'], bytes.fromhex(cert['source'])[-32:])
            assert source.bytes().hex() == cert['source']
            handle = pcs.verify_certificate(source, bytes.fromhex(cert['certificate']))
            assert handle.identity.hex() == cert['id']
            originals.append(handle)
        mu = [pcs.Source(d, v['id'], v['ell'], (n*d).bit_length()-1-v['ell'], v['blowup'], bytes(32)) for v in case['multiplicities']]
        return dict(desc=desc, real=real, n=n, c=c, originals=originals, mu=mu, setup=output['originals'])

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

    def verify(case, g):
        d, m, b, identity = (case[k] for k in ('degree', 'm', 'b', 'lookup_id'))
        zero, one = sc.scalar(0, d), sc.scalar(1, d)
        out = dict(name=case['name'], degree=d, originals=g['setup'], phase='import', registrations=[None, None])
        handles = []
        cap = sum(len(b'stele/v0.1/pcs-certificate/public')+105+size(s, 0)-1 for s in g['mu'])
        try:
            require(cap <= case.get('import_cap', cap), 'ResourceLimit')
            packets, _ = parse(case, g, bytes.fromhex(case.get('registration_proof', case['proof'])))
            for j, (source, certificate, _) in enumerate(packets):
                local, before = o.hashes(), len(o.CREATED)
                try:
                    with o.local_hashes(local):
                        handles.append(wrapped('Pcs', pcs.verify_certificate, source, certificate))
                finally:
                    assert len(o.CREATED) == before+1
                    out['registrations'][j] = dict(transcript=o.CREATED[-1].usage.copy(), non_transcript=local)
        except ValueError as error:
            out['decision'] = str(error)
            return out
        out['phase'] = 'outer'
        t, local = o.Transcript(bytes.fromhex(case['public_hex']), d), o.hashes()
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
        if out['decision'] == 'accept':
            out['continuation'] = t.challenge()[0].hex()
        return out

    cases, expected = [], []

    def add(case, g, decision='accept', phase='outer'):
        case = dict(case, mode='verify')
        cases.append(case)
        result = verify(case, g)
        assert (result['phase'], result['decision']) == (phase, decision), (case['name'], result['phase'], result['decision'])
        expected.append(result)

    for original, output in zip(inputs, produced):
        if output['outcome'] != 'produced':
            continue
        case = dict(original, name='closed-'+original['name'], proof=output['proof'])
        g = geometry(case, output)
        add(case, g)
        if not original['name'].startswith('partial'):
            continue
        d = case['degree']
        raw = bytes.fromhex(output['proof'])
        packets, reps = parse(case, g, raw)
        s = packets[0][0]
        point = [pcs.fields(bytes.fromhex(v), d)[0] for v in expected[-1]['record']['repetitions'][0]['table']['point']]
        assert coefficients(s, point, g['real'])[0][2][0] != sc.scalar(0, d), 'row tamper must reach scalar mismatch'
        start = reps[0]['openings'][0][1]
        mutations = [
            ('truncated', raw[:-1]), ('trailing', raw+b'\0'), ('header', bytes([2])+raw[1:]),
        ]
        for name, offset, replacement in [
            ('identity', packets[0][2]+1, None),
            ('piece', reps[0]['value_start'], None),
            ('row', start+1, None),
            ('tree', reps[0]['left_start'], None),
            ('noncanonical-tree', reps[-1]['left_start'], sc.P),
            ('noncanonical-piece', reps[0]['value_start'], sc.P),
            ('noncanonical-row', start+1, sc.P),
            ('unauthenticated-column', start+1+4*d*(1 << s.m), sc.P),
        ]:
            changed = bytearray(raw)
            if replacement is None:
                value = pcs.fields(raw[offset:offset+4*d], d)[0]
                changed[offset:offset+4*d] = sc.encode(sc.add(value, sc.scalar(1, d)))
            else:
                changed[offset:offset+4] = struct.pack('<I', replacement)
            mutations.append((name, bytes(changed)))
        path = start+1+4*d*(1 << s.m)+4*(1 << s.ell)
        changed = bytearray(raw); changed[path] ^= 1
        mutations.append(('mu-path', bytes(changed)))
        decisions = dict(truncated='ProofShape', trailing='ProofShape', header='ProofShape',
            identity='CertificateIdentity', piece='PieceSumMismatch', row='Pcs(ValueMismatch)',
            tree='Fraction(Sumcheck(FinalEvaluationMismatch))', **{'noncanonical-tree':'Fraction(NoncanonicalField)',
            'noncanonical-piece':'ProofShape', 'noncanonical-row':'Pcs(NoncanonicalField)',
            'unauthenticated-column':'Pcs(Merkle(RootMismatch))', 'mu-path':'Pcs(Merkle(RootMismatch))'})
        for name, changed in mutations:
            add(dict(case, name=f'{name}-{d}', proof=changed.hex(), registration_proof=raw.hex()), g, decisions[name])
        last, _, offset = packets[-1]
        changed = bytearray(raw); changed[offset+1+4*d*(1 << last.m)+4*(1 << last.ell)] ^= 1
        add(dict(case, name=f'import-path-{d}', registration_proof=changed.hex()), g, 'Pcs(Merkle(RootMismatch))', 'import')
        cap = sum(len(b'stele/v0.1/pcs-certificate/public')+105+size(s, 0)-1 for s in g['mu'])
        add(dict(case, name=f'import-cap-{d}', import_cap=cap-1), g, 'ResourceLimit', 'import')
        add(dict(case, name=f'import-shape-{d}', registration_proof=raw[:-1].hex()), g, 'ProofShape', 'import')
        # A separately prepared/certified root is genuine authority for its source,
        # but must not match the unchanged candidate's expected registration packet.
        alt, witness = pcs.commit([[17]*(1 << s.m) for _ in range(1 << s.ell)], s.ell, s.m, s.blowup, d, s.identity)
        cert = pcs.certify(alt, witness)
        changed = bytearray(raw); offset = packets[0][2]
        changed[offset-32:offset] = alt.root; changed[offset:offset+len(cert)] = cert
        add(dict(case, name=f'context-{d}', registration_proof=changed.hex()), g, 'CertificateContext')
        tail = copy.deepcopy(original)
        tail.update(name=f'tail-{d}', physical_tail=True, selector=[0]*len(tail['selector']))
        for source in tail['originals']:
            source['message'] = [256]*len(source['message'])
        tail_output = o.reference(tail)
        assert tail_output['outcome'] == 'produced'
        add(dict(tail, proof=tail_output['proof']), geometry(tail, tail_output))
    return cases, expected
