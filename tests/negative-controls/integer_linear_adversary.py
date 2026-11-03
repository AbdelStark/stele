"""RFC-0024 §6 untrusted complete false-advice regression producers.

Keep true C=0 and the same expected Q=0. Change one captured accumulator, then
regenerate genuine advice registrations and all dependent proof messages.
These are the specified cap/join regressions, not additional catalog controls.
"""
from integer_linear_reference import Operation, Schema, RANGE_PUBLIC, source_range_case, following_instance, need
from integer_linear_producer import arithmetic, prove_range, produce


def advice(schema, accumulator):
    """Canonical old Requant advice plus the adversary's wrapped 32-bit slack."""
    old = schema.semantic.witness(accumulator)
    row = old[1:5]+old[5:5+schema.semantic.L]
    slack = (schema.bound-abs(accumulator)) % (1 << 32)
    row += list(slack.to_bytes(4, 'little'))
    carry, carries = 0, []
    for k in range(4):
        total = ((abs(accumulator) >> (8*k)) & 255)+((slack >> (8*k)) & 255)+carry
        need(total % 256 == ((schema.bound >> (8*k)) & 255), 'AdversaryLowBytes')
        carry = total//256
        if k < 3:
            carries.append(carry)
    row += carries+[0]*(schema.R-len(row)-3)
    need(len(row) == schema.R and all(0 <= v < 256 for v in row), 'AdversaryByteAdvice')
    # This audit isolates the new high cap equation; the old semantic equations,
    # boolean carries and every physical padding plane remain satisfied.
    values, violations = [1, *row], []
    for index, (_, terms) in enumerate(schema.constraints):
        value = 0
        for coefficient, factors in terms:
            product = coefficient
            for factor in factors:
                product *= values[factor]
            value += product
        if value:
            violations.append((index, value))
    boundary = next(i for i,(name,_) in enumerate(schema.semantic.constraints()) if name == 'target')+1
    if abs(accumulator) <= schema.bound:
        need(not violations and carry == 0, 'AdversaryHonestEquations')
        need([[v] for v in row] == schema.witness([accumulator]), 'AdversaryHonestWitness')
    else:
        need(violations == [(boundary+3, 256)] and carry == 1, 'AdversaryCapIsolation')
    return [[v] for v in row]


def regressions(ref, degree, repetitions):
    pcs, sc = ref.pcs, ref.sc
    packets, witnesses, originals = [], [], []
    for index, (message, rate, identity, ids) in enumerate(zip((128, 130), (1, 2),
            (101, 102), ([111, 112][:repetitions], [121, 122][:repetitions]), strict=True)):
        source, witness = pcs.commit([[message]], 0, 0, rate, degree, identity)
        handle, packet, _, _ = ref.o.register(source, witness)
        case = source_range_case(degree, source, 9+index, ids)
        wire, _ = prove_range(ref, ref.Transcript(RANGE_PUBLIC, degree), case, handle, witness)
        packets.append(dict(source=source, certificate=packet, lookup_id=9+index, mu_ids=ids, range_proof=wire))
        witnesses.append(witness)
        originals.append(dict(source_hex=source.bytes().hex(), certificate_hex=packet.hex(),
            lookup_id=9+index, mu_ids=ids, range_proof_hex=wire.hex()))
    schema = Schema(ref, [0]*4, 1, 62, 16, 31)
    public = b'RFC0024/full cap and join regressions/v1'
    operation = Operation(ref, schema, degree, repetitions, packets, [], sc.scalar(0, degree), public, 2)
    for name, captured, expected in (
            ('honest_zero', 0, 'accept'),
            ('in_range_one', 1, 'Matmul(Stacked(Sumcheck(FinalEvaluationMismatch)))'),
            ('field_alias', sc.P, 'Sumcheck(FinalEvaluationMismatch)'),
            ('bound_plus_one', schema.bound+1, 'Sumcheck(FinalEvaluationMismatch)'),
            ('full_width_high', -(1 << 31), 'Sumcheck(FinalEvaluationMismatch)')):
        matrix = advice(schema, captured)
        source, witness = pcs.commit(matrix, schema.a0, 0, 2, degree, schema.S+2)
        owner, packet, _, _ = ref.o.register(source, witness)
        wire, transcript, used = produce(operation, witnesses, witness, owner, packet)
        following, _ = sc.prove(transcript, following_instance(operation), [[sc.scalar(1, degree), sc.scalar(2, degree)]])
        yield dict(name=name, degree=degree, repetitions=repetitions, captured=captured, expected=expected,
            producer_usage=used, request=dict(degree=degree, stage=31, dims=[0]*4,
                parameters=dict(mantissa=1, shift=62, bits=16), repetitions=repetitions, advice_blowup=2,
                point=[], value=sc.scalar(0, degree), public_hex=public.hex(), originals=originals,
                proof_hex=wire.hex(), following_hex=arithmetic(pcs, following).hex()))


if __name__ == '__main__':
    import argparse
    import json
    import sys
    from integer_linear_reference import load
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'Runtime')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('degree', type=int, choices=(4, 8))
    parser.add_argument('repetitions', type=int, choices=(1, 2))
    args = parser.parse_args()
    with load() as ref:
        for case in regressions(ref, args.degree, args.repetitions):
            print(json.dumps(case, separators=(',', ':')), flush=True)
