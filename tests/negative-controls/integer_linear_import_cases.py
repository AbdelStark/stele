"""RFC-0024 malformed/import regressions; no additional catalog-control credit."""
from copy import deepcopy
from integer_linear_reference import decode_request, need


def requests(ref, request):
    """Mutate fixed public packets, then use fresh closed verifiers for each case."""
    operation, wire, _ = decode_request(ref, request)
    _, parts = operation.partition(wire)
    d, r = operation.d, operation.repetitions
    yield dict(name='honest', expected='accept', phase=None, request=request)

    def case(name, path, at, replacement, expected, phase):
        changed = deepcopy(request)
        parent = changed
        for key in path[:-1]:
            parent = parent[key]
        original = bytes.fromhex(parent[path[-1]])
        if replacement is None:
            replacement = bytes([original[at] ^ 1])
        raw = original[:at]+replacement+original[at+len(replacement):]
        need(raw != original and len(raw) == len(original), 'OnePacketMutation')
        parent[path[-1]] = raw.hex()
        return dict(name=name, expected=expected, phase=phase, request=changed)

    for index, owner in enumerate(operation.originals):
        path = ('originals', index, 'certificate_hex')
        length = len(bytes.fromhex(request['originals'][index]['certificate_hex']))
        yield case(f'original-{index}-path', path, length-1, None, 'Merkle(RootMismatch)', 'original-import')
        yield case(f'original-{index}-noncanonical', path, 1, ref.sc.P.to_bytes(4, 'little'),
                   'NoncanonicalField', 'original-import')
        info = request['originals'][index]
        from integer_linear_reference import source_range_case
        policy = source_range_case(d, owner.source, info['lookup_id'], info['mu_ids'])
        geometry = operation.adapter.geometry(policy, [owner])
        raw = bytes.fromhex(info['range_proof_hex'])
        packets, repetitions = operation.adapter.parse(policy, geometry, raw)
        for j, (_, certificate, offset) in enumerate(packets):
            yield case(f'original-{index}-mu-{j}-path', ('originals', index, 'range_proof_hex'),
                       offset+len(certificate)-1, None, 'Pcs(Merkle(RootMismatch))', 'original-multiplicity-import')
        opening, offset = repetitions[0]['originals'][0]
        value = int.from_bytes(opening[1:5], 'little')
        need(value+1 < ref.sc.P, 'CanonicalChangedRow')
        yield case(f'original-{index}-range-row', ('originals', index, 'range_proof_hex'),
                   offset+1, (value+1).to_bytes(4, 'little'), 'Pcs(ValueMismatch)', 'original-range')
    yield case('advice-path', ('proof_hex',), 34+len(parts[0])-1, None, 'Merkle(RootMismatch)', 'advice-import')
    yield case('advice-noncanonical', ('proof_hex',), 35, ref.sc.P.to_bytes(4, 'little'),
               'NoncanonicalField', 'advice-import')
    source = ref.pcs.Source(d, operation.s.S+2, operation.s.a0, operation.s.m, operation.blowup, wire[2:34])
    advice = ref.pcs.verify_certificate(source, parts[0])
    policy, geometry = operation.advice_geometry(advice)
    packets, _ = operation.adapter.parse(policy, geometry, parts[1])
    need(len(packets) == r, 'MultiplicityInventory')
    for j, (_, certificate, offset) in enumerate(packets):
        yield case(f'advice-mu-{j}-path', ('proof_hex',), 34+len(parts[0])+offset+len(certificate)-1,
                   None, 'Lookup(Pcs(Merkle(RootMismatch)))', 'multiplicity-import')
    yield case('outer-version', ('proof_hex',), 0, None, 'ProofShape', 'multiplicity-import')
    yield case('advice-lookup-version', ('proof_hex',), 34+len(parts[0]), None,
               'Lookup(ProofShape)', 'multiplicity-import')
    yield case('arithmetic-noncanonical', ('proof_hex',), 34+len(parts[0])+len(parts[1]),
               ref.sc.P.to_bytes(4, 'little'), 'NoncanonicalField', 'multiplicity-import')
    for name, changed_wire in (('short', wire[:-1]), ('trailing', wire+b'\0')):
        changed = deepcopy(request)
        changed['proof_hex'] = changed_wire.hex()
        yield dict(name=name, expected='ProofShape', phase='multiplicity-import', request=changed)
