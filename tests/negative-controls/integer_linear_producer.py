"""RFC-0024 independent untrusted producer using the unchanged Python engines.

This module constructs messages; only integer_linear_reference verifies them.
Original ranges, advice and every opening are produced in the actual transcript.
"""
import struct
from integer_linear_reference import Operation, Schema, LINEAR, MATMUL, RANGE_PUBLIC, need, source_range_case, following_instance


def arithmetic(pcs, proof, zero=False):
    final = [v for row in proof['final'] for v in row] if zero else proof['final']
    return pcs.field_bytes([v for row in proof['rounds'] for v in row]+final)


def prove_range(ref, t, case, handle, witness):
    """Fixed whole-source range_8 A5, retaining the all-mu-before-pairs order."""
    o, pcs, sc, ft = ref.o, ref.pcs, ref.sc, ref.ft
    d, m, b, identity = (case[k] for k in ('degree', 'm', 'b', 'lookup_id'))
    need(m == b and case['selector'] == [1]*(1 << m), 'ReferenceRangeScope')
    need(case['table'] == dict(name='range_8', version=1, params_hex=''), 'ReferenceRangeScope')
    need(all(v['ell'] == 0 and v['blowup'] == 1 for v in case['multiplicities']), 'ReferenceRangeScope')
    zero, one = sc.scalar(0, d), sc.scalar(1, d)
    table = ref.ti.Descriptor('range_8', 1, b'')
    rows = ref.ti.canonical_rows(table)
    need(len(rows) == 256, 'ReferenceRangeScope')
    t.absorb(o.STATEMENT, o.statements(case, table, [handle]))
    layouts = case['multiplicities']
    for j in range(len(layouts)):
        t.absorb(o.UNITS, struct.pack('<QB', identity, j))
    message = [v for row in witness[0] for v in row]
    need(len(message) == 1 << m and all(type(v) is int and 0 <= v < 256 for v in message), 'RangeWitness')
    histogram = [0]*256
    for v in message:
        histogram[v] += 1
    mu = [sc.scalar(v, d) for v in histogram]
    out, prepared, owners, registrations = bytearray([1, d]), [], [], []
    bundle = struct.pack('<QB', identity, len(layouts))
    for j, layout in enumerate(layouts):
        source, data = pcs.commit([[limb for v in mu for limb in v]], 0,
            8+d.bit_length()-1, 1, d, layout['id'])
        owner, packet, usage, _ = o.register(source, data)
        prepared.append(data)
        owners.append(owner)
        registrations.append(usage)
        bundle += bytes([j])+source.bytes()+owner.identity
        out += source.root+packet
    t.absorb(o.MULTIPLICITIES, bundle)
    pairs = []
    for j in range(len(layouts)):
        t.absorb(o.REPETITION, struct.pack('<QBB', identity, j, 0))
        pairs.append((t.field(o.BETA), t.field(o.ALPHA)))
    sigma, xs = [one]*(1 << m), [[sc.scalar(v, d) for v in message]]
    for j, (beta, alpha) in enumerate(pairs):
        t.absorb(o.REPETITION, struct.pack('<QBB', identity, j, 1))
        left = dict(id=4*identity+2*j, m=m, b=m, leaves=(8*identity+4*j, 8*identity+4*j+1), theta=[])
        right = dict(id=left['id']+1, m=8, b=8, leaves=(left['leaves'][0]+2, left['leaves'][0]+3), theta=[])
        lp, lr = ft.prove(t, left, ft.lookup_leaves(sigma, xs, alpha, beta, d))
        out += ft.proof_bytes(left, lp, d)
        leaves = [(mu[i], sc.add(alpha, sc.neg(sc.scalar(row[0], d)))) for i, row in enumerate(rows)]
        rp, rr = ft.prove(t, right, leaves)
        out += ft.proof_bytes(right, rp, d)
        ft.root_equation(lp['root'], rp['root'], d)
        proof, reduced = ft.prove_leaf(t, left, lr, sigma, [handle.source.identity], xs, alpha, beta)
        out += arithmetic(pcs, proof)
        point = reduced['point']
        out += pcs.open_functional(t, handle.source.identity, handle, witness,
            pcs.eq(point[:handle.source.ell], d), pcs.eq(point[handle.source.ell:], d), reduced['claims'][0][1])
        point, value = rr['point'], rr['values'][0]
        suffix = pcs.eq(point, d)
        need(pcs.dot(mu, suffix, d) == value, 'MultiplicityClaim')
        basis = [tuple(int(i == k) for i in range(d)) for k in range(d)]
        columns = [sc.mul(v, e) for v in suffix for e in basis]
        out += sc.encode(value)
        t.absorb(o.CLAIMS, struct.pack('<QBB', identity, j, 1)+pcs.field_bytes([*point, value])+b'\0'+sc.encode(value))
        out += pcs.open_functional(t, 0, owners[j], prepared[j], [one], columns, value)
    return bytes(out), registrations+[None]*(2-len(registrations))


def retained_opening(ref, t, owner, witness, weights, columns, value, row):
    """Serialize the actual once-computed raw row; never rescan its message."""
    pcs, s = ref.pcs, owner.source
    need(pcs.dot(row, columns, s.degree) == value, 'OriginalClaim')
    pcs.opening_instance(t, s.identity, owner, weights, columns, value)
    t.absorb(pcs.OPEN_ROW, pcs.field_bytes(row))
    block = pcs.responses(t, s, witness, pcs.OPEN_COLUMN, pcs.counts(s.m, s.blowup)[1])
    t.absorb(pcs.OPEN_COLUMNS, block)
    return b'\1'+pcs.field_bytes(row)+block


def produce(operation, original_witnesses, advice_witness, advice, packet):
    ref, s, d = operation.ref, operation.s, operation.d
    pcs, sc = ref.pcs, ref.sc
    t, local = ref.Transcript(operation.public, d), ref.o.hashes()
    with ref.o.local_hashes(local):
        operation.check_advice_packet(advice.source, packet, advice)
        t.absorb(LINEAR, operation.statement(advice))
        case, _ = operation.advice_geometry(advice)
        lookup, registrations = prove_range(ref, t, case, advice, advice_witness)
        aggregate = operation.aggregate(t)
        one = sc.scalar(1, d)
        tables = [[one]*s.N]+[[sc.scalar(v, d) for v in row] for row in advice_witness[0]]
        before = len(t.draw_trace)
        zero = ref.zc.prove(t, aggregate, tables)
        point = [v for label, v in t.draw_trace[before:] if label == pcs.CHALLENGE]
        need(len(point) == s.m, 'ActualAggregatePoint')
        values = [row[0] for row in zero['final']]
        groups = []
        for index, rows, ids, finals in (
                (0, list(range(4)), s.ids[1:5], values[1:5]),
                (1, list(range(4, s.R)), s.ids[5:], values[5:])):
            identity, a, b, value, _ = operation.group(t, index, advice, point, rows, ids, finals)
            groups.append(pcs.open_functional(t, identity, advice, advice_witness, a, b, value))
        join_point = list(point)
        join_value = sc.add(sc.scalar(-(1 << 31), d), pcs.dot(
            [sc.scalar(256**k, d) for k in range(4)], values[1:5], d))
        coefficients = pcs.eq(operation.z, d)
        output_tables = [coefficients]+[tables[row+1] for row in operation.output_rows]
        output, point = sc.prove(t, operation.output, output_tables)
        identity, a, b, value, _ = operation.group(t, 2, advice, point, operation.output_rows,
            operation.output['ids'][1:], output['final'][1:])
        groups.append(pcs.open_functional(t, identity, advice, advice_witness, a, b, value))
        statement, frame = operation.matmul_statement(join_point, join_value)
        h, a, _, _ = s.dims
        outer = [join_point[h:h+a], join_point[h+a:]]
        weights = [pcs.eq(p, d) for p in outer]
        raw_rows = [pcs.row(witness[0], a, d) for witness, a in zip(original_witnesses, weights, strict=True)]
        sums = [pcs.dot(a, [one]*len(a), d) for a in weights]
        signed = [[sc.add(v, sc.neg(sc.mul(sc.scalar(128, d), total))) for v in row]
                  for row, total in zip(raw_rows, sums, strict=True)]
        t.absorb(MATMUL, frame)
        before = len(t.draw_trace)
        matmul = ref.stage.prove(t, statement, signed)
        point = [v for label, v in t.draw_trace[before:] if label == pcs.CHALLENGE]
        need(len(point) == s.dims[0]+s.dims[2], 'ActualMatmulPoint')
        columns = pcs.eq(point, d)
        col_sum = pcs.dot(columns, [one]*len(columns), d)
        suffix = b'\1'+arithmetic(pcs, matmul)
        for owner, witness, a, total, value, row in zip(operation.originals, original_witnesses,
                weights, sums, matmul['final'][:2], raw_rows, strict=True):
            raw_value = sc.add(value, sc.mul(sc.scalar(128, d), sc.mul(total, col_sum)))
            suffix += retained_opening(ref, t, owner, witness, a, columns, raw_value, row)
        wire = (bytes([1, d])+advice.source.root+packet+lookup+arithmetic(pcs, zero, zero=True)
                +groups[0]+groups[1]+arithmetic(pcs, output)+groups[2]+suffix)
        need(len(wire) == 34+sum(operation.sizes()), 'ProducedShape')
    usage = dict(transcript=t.usage.copy(), non_transcript=local, registrations=registrations)
    return wire, t, usage


CASES = dict(
    scalar=([0, 0, 0, 0], 1, 1, 8), stacked=([1, 1, 1, 1], 1, 1, 8),
    ties=([0, 0, 0, 2], 1, 1, 8), zero_x=([1, 1, 1, 0], 32767, 62, 16),
    zero_w=([0, 1, 1, 1], 1, 0, 8), wide=([1, 1, 0, 1], 32767, 15, 16),
    shift62=([0, 1, 1, 1], 32767, 62, 16), int16_min=([0, 0, 2, 0], 1, 0, 16),
    int16_max=([0, 0, 2, 0], 1, 0, 16), int8_min=([0, 0, 0, 0], 1, 0, 8),
    int8_max=([0, 0, 0, 0], 1, 0, 8), cap=([0, 0, 0, 0], 1, 8, 8))


def fixture(ref, degree, scenario, repetitions):
    """Small deterministic signed matrices, generated independently of native output."""
    pcs, sc = ref.pcs, ref.sc
    dims, mantissa, shift, bits = CASES[scenario]
    h, a, b, c = dims
    size, layers, inner = 1 << (h+b), 1 << h, 1 << b
    messages = [[125+i % 7 for i in range((1 << a)*size)],
                [126+i % 5 for i in range((1 << c)*size)]]
    if scenario == 'ties':
        messages = [[127], [127, 129, 125, 131]]
    elif scenario == 'zero_x':
        messages[0] = [128]*len(messages[0])
    elif scenario == 'zero_w':
        messages[1] = [128]*len(messages[1])
    elif scenario == 'wide':
        messages = [[0, 255, 129, 127], [255, 0, 127, 129]]
    elif scenario == 'int16_min':
        messages = [[0]*4, [192]*4]
    elif scenario == 'int16_max':
        messages = [[255, 255, 255, 129], [255, 255, 132, 129]]
    elif scenario == 'int8_min':
        messages = [[0], [129]]
    elif scenario == 'int8_max':
        messages = [[255], [129]]
    elif scenario == 'cap':
        messages = [[0], [0]]
    matrices = [[message[i:i+size] for i in range(0, len(message), size)] for message in messages]
    base_point = scenario in ('scalar', 'stacked')
    rates = (1, 2, 1) if base_point else (2, 1, 2)
    captured = [sum((matrices[0][i][l*inner+k]-128)*(matrices[1][j][l*inner+k]-128)
                    for k in range(inner)) for l in range(layers) for i in range(1 << a) for j in range(1 << c)]
    packets, witnesses, originals = [], [], []
    for index, (matrix, ell, rate, identity, mu_ids) in enumerate(zip(matrices, (a, c), rates[:2],
            (101, 102), ([111, 112][:repetitions], [121, 122][:repetitions]), strict=True)):
        source, witness = pcs.commit(matrix, ell, h+b, rate, degree, identity)
        handle, packet, _, _ = ref.o.register(source, witness)
        case = source_range_case(degree, source, 9+index, mu_ids)
        range_proof, _ = prove_range(ref, ref.Transcript(RANGE_PUBLIC, degree), case, handle, witness)
        packets.append(dict(source=source, certificate=packet, lookup_id=9+index, mu_ids=mu_ids, range_proof=range_proof))
        witnesses.append(witness)
        originals.append(dict(source_hex=source.bytes().hex(), certificate_hex=packet.hex(),
                              lookup_id=9+index, mu_ids=mu_ids, range_proof_hex=range_proof.hex()))
    schema = Schema(ref, dims, mantissa, shift, bits, 31)
    matrix = schema.witness(captured)
    source, witness = pcs.commit(matrix, schema.a0, schema.m, rates[2], degree, schema.S+2)
    advice, packet, _, _ = ref.o.register(source, witness)
    point = [sc.scalar(i+2, degree) if base_point else tuple((i+2)*(j+1) for j in range(degree))
             for i in range(schema.m)]
    bias = 0 if shift == 0 else 1 << (shift-1)
    outputs = [(-1 if v < 0 else 1)*((abs(v)*mantissa+bias) >> shift) for v in captured]
    value = pcs.dot(pcs.eq(point, degree), [sc.scalar(v, degree) for v in outputs], degree)
    public = b'complete centered integer linear'
    operation = Operation(ref, schema, degree, repetitions, packets, point, value, public, rates[2])
    wire, t, usage = produce(operation, witnesses, witness, advice, packet)
    following, _ = sc.prove(t, following_instance(operation), [[sc.scalar(1, degree), sc.scalar(2, degree)]])
    return dict(request=dict(degree=degree, stage=31, dims=list(dims),
                parameters=dict(mantissa=mantissa, shift=shift, bits=bits), repetitions=repetitions, advice_blowup=rates[2],
                point=point, value=value, public_hex=public.hex(), originals=originals,
                proof_hex=wire.hex(), following_hex=arithmetic(pcs, following).hex()), producer_usage=usage)


if __name__ == '__main__':
    import argparse
    import json
    import sys
    from integer_linear_reference import load
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'Runtime')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('degree', type=int, choices=(4, 8))
    parser.add_argument('case', choices=tuple(CASES))
    parser.add_argument('repetitions', type=int, choices=(1, 2))
    args = parser.parse_args()
    with load() as ref:
        print(json.dumps(fixture(ref, args.degree, args.case,
                                 args.repetitions), sort_keys=True, separators=(',', ':')))
