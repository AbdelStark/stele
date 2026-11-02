"""RFC-0024 independent composition over the existing Python A3/A4/A5/A9 engines.

No native receipt or plaintext matrix will authorize a verifier claim. The old
Requant and matmul reference modules remain unchanged.
"""
from contextlib import contextmanager
import importlib
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'tests/negative-controls'))
sys.path.insert(0, str(ROOT/'tests/negative-controls/requant'))
from reference import load as load_requant
from protocol_reference import Protocol, Reader, Schema as RequantSchema, need, public_eq
from requant_schema import Schema as SemanticSchema
from embedded_requant import embedded

LINEAR = b'stele/v0.1/integer-linear/statement'
MATMUL = b'stele/v0.1/matmul/statement'
RANGE_PUBLIC = b'stele/v0.1/integer-linear/byte-range/v1'


class VerificationAbort(ValueError):
    """An actual early consumer failure, retaining only its executed prefix."""
    def __init__(self, result):
        super().__init__(result['decision'])
        self.result = result


def consumer(kind, call, *args):
    """Keep the native composition's exact wrappers around actual engine failures."""
    try:
        return call(*args)
    except ValueError as error:
        name = str(error)
        if kind in ('Pcs', 'MatmulPcs'):
            need(name in ('ProofShape', 'NoncanonicalField', 'ValueMismatch', 'ColumnMismatch', 'RootMismatch'), 'UnclassifiedPcsFailure')
            if kind == 'MatmulPcs' and name in ('ProofShape', 'NoncanonicalField'):
                raise
            name = 'Merkle(RootMismatch)' if name == 'RootMismatch' else name
            name = f'Pcs({name})'
            if kind == 'MatmulPcs':
                name = f'Matmul({name})'
        elif kind in ('Sumcheck', 'MatmulStacked'):
            need(name in ('ProofShape', 'NoncanonicalField', 'RoundSumMismatch', 'FinalEvaluationMismatch', 'CoefficientMismatch'), 'UnclassifiedArithmeticFailure')
            if name != 'CoefficientMismatch':
                name = f'Sumcheck({name})'
            if kind == 'MatmulStacked':
                name = f'Matmul(Stacked({name}))'
        elif kind == 'Lookup':
            name = f'Lookup({name})'
        else:
            raise AssertionError(kind)
        raise ValueError(name) from error


@contextmanager
def load(root=ROOT):
    """One shared field/transcript implementation, scoped to this new operation."""
    with load_requant(root) as ref:
        stage = importlib.import_module('stage')
        need(Path(stage.__file__).resolve() == root/'research/stacked-gkr/stage.py', 'ReferenceSource')
        need(stage.sc is ref.sc, 'ReferenceField')
        base = ref.Transcript

        class Transcript(base):
            def absorb(self, label, payload):
                if label in (LINEAR, MATMUL, stage.STACK):
                    self.state = ref.o.raw_hash(ref.pcs.frame(self.state, 0, label, payload)).digest()
                    self.usage['hash_evaluations'] += 1
                    self.usage['state_updates'] += 1
                    self.public_bytes += len(payload)
                else:
                    super().absorb(label, payload)

        ref.stage = stage
        ref.Transcript = ref.pcs.Transcript = ref.o.Transcript = Transcript
        try:
            yield ref
        finally:
            ref.Transcript = ref.pcs.Transcript = ref.o.Transcript = base


class Schema:
    """Independent full-width embedded compiler and one physical advice matrix."""
    def __init__(self, ref, dims, mantissa, shift, bits, stage):
        need(len(dims) == 4 and all(type(b) is int and 0 <= b <= 63 for b in dims), 'Statement')
        h, a, b, c = dims
        need(1 <= stage < 2**20 and h+a+c <= 63, 'Statement')
        need(b <= 15, 'Bounds(FieldBound)')
        self.semantic = SemanticSchema(mantissa, shift, bits)
        self.bound, self.R, equations = embedded(self.semantic, b)
        self.ref, self.stage, self.S = ref, stage, stage << 40
        self.dims, self.m = list(dims), h+a+c
        self.n = self.N = 1 << self.m
        self.a0 = self.R.bit_length()-1
        self.spec, self.blocks = self.semantic.spec, self.semantic.blocks
        self.bound_bytes = self.semantic.bound_bytes
        self.ids = [self.S+(1 << 28)]+[self.S+(1 << 24)+row for row in range(self.R)]
        self.constraints = [(f'embedded[{i}]', terms) for i, terms in enumerate(equations)]

    instances = RequantSchema.instances

    def output_instance(self, degree, value):
        instance, rows = RequantSchema.output_instance(self, degree, value)
        return instance, [row+4 for row in rows]

    def witness(self, captured):
        """Untrusted canonical advice from captured C; never read X or W here."""
        need(len(captured) == self.N, 'WitnessShape')
        positions = []
        for acc in captured:
            need(type(acc) is int and abs(acc) <= self.bound, 'WitnessBound')
            old = self.semantic.witness(acc)
            row = old[1:5]+old[5:5+self.semantic.L]
            slack, carry = self.bound-abs(acc), 0
            row += list(slack.to_bytes(4, 'little'))
            carries = []
            for k in range(4):
                total = ((abs(acc) >> (8*k)) & 255)+((slack >> (8*k)) & 255)+carry
                need(total % 256 == (self.bound >> (8*k)) & 255, 'WitnessCarry')
                carry = total//256
                if k < 3:
                    carries.append(carry)
            need(carry == 0, 'WitnessCarry')
            row += carries
            row += [0]*(self.R-len(row))
            need(len(row) == self.R, 'WitnessShape')
            positions.append(row)
        return [list(row) for row in zip(*positions, strict=True)]


def source_range_case(degree, source, identity, mu_ids):
    """Expected whole-source range policy; no packet-derived selector or ids."""
    m = source.ell+source.m
    return dict(name='integer-linear-original-range', degree=degree, m=m, b=min(m, 30),
                lookup_id=identity, table=dict(name='range_8', version=1, params_hex=''),
                selector=[1]*(1 << m),
                originals=[dict(id=source.identity, ell=source.ell, blowup=source.blowup)],
                multiplicities=[dict(id=i, ell=0, blowup=1) for i in mu_ids])


def range_binding(identity, handles):
    return (struct.pack('<BQB', 1, identity, len(handles))
            + b''.join(h.source.bytes()+h.identity for h in handles))


class Operation:
    """Concrete expected RFC-0024 operation; no old two-source descriptor is aliased."""
    observed = Protocol.observed
    constraints_frame = Protocol.constraints_frame
    aggregate = Protocol.aggregate
    group = Protocol.group
    arithmetic_read = Protocol.arithmetic_read
    check_advice_packet = Protocol.check_advice_packet

    def __init__(self, ref, schema, degree, repetitions, packets, z, value, public, blowup=1):
        self.ref, self.s, self.d = ref, schema, degree
        self.pcs, self.sc = ref.pcs, ref.sc
        self.repetitions, self.blowup = repetitions, blowup
        self.z, self.value, self.public = z, value, public
        self.observations, self.originals, self.ranges = [], [], []
        self.imports = dict(originals=[], original_multiplicities=[], advice=None, multiplicities=None)
        ref.degree = degree
        need(degree in (4, 8) and repetitions in (1, 2) and blowup in (1, 2), 'Parameters')
        need(len(z) == schema.m and len(packets) == 2, 'Statement')
        self.pcs.fields(self.pcs.field_bytes([*z, value]), degree)
        from integer_linear_lookup import Lookup
        self.adapter = Lookup(ref.o)
        h, a, b, c = schema.dims
        need(schema.R*schema.N+(1 << (h+b))*((1 << a)+(1 << c)) <= 65536, 'ResourceLimit')
        for index, (packet, ell) in enumerate(zip(packets, (a, c), strict=True)):
            source = packet['source']
            need((source.degree, source.ell, source.m) == (degree, ell, h+b), 'SourceRoster')
            need(2 <= source.identity < 2**64 and not schema.S <= source.identity < schema.S+(1 << 40), 'SourceRoster')
            need(0 <= packet['lookup_id'] < 2**60 and len(packet['mu_ids']) == repetitions, 'SourceRoster')
            range_ids = [source.identity, *packet['mu_ids']]
            need(all(type(identity) is int and 2 <= identity < 2**64 for identity in range_ids)
                 and len(set(range_ids)) == len(range_ids), 'SourceRoster')
            need(not schema.S <= packet['lookup_id']*16 < schema.S+(1 << 40), 'SourceRoster')
            need(all(not schema.S <= identity < schema.S+(1 << 40) for identity in packet['mu_ids']), 'SourceRoster')
            original = self.import_certificate(source, packet['certificate'], index)
            self.originals.append(original)
        need(self.originals[0].source.identity != self.originals[1].source.identity, 'SourceRoster')
        prepared = []
        for index, (packet, original) in enumerate(zip(packets, self.originals, strict=True)):
            source = original.source
            case = source_range_case(degree, source, packet['lookup_id'], packet['mu_ids'])
            geometry = self.adapter.geometry(case, [original])
            case['proof'] = packet['range_proof'].hex()
            imported = self.adapter.register(case, geometry)
            self.imports['original_multiplicities'].append(imported['registrations'])
            if imported['decision'] != 'accept':
                self.abort(imported['decision'], 'original-multiplicity-import', index=index)
            prepared.append((case, geometry, imported))
        for index, (case, geometry, imported) in enumerate(prepared):
            transcript = ref.Transcript(RANGE_PUBLIC, degree)
            receipt = self.adapter.consume(case, geometry, transcript, imported)
            if receipt['decision'] != 'accept':
                self.abort(receipt['decision'], 'original-range', index=index, usage=receipt['usage'])
            owners = receipt['_retained_mu_handles']
            need(len(owners) == repetitions, 'SourceRoster')
            self.ranges.append(dict(identity=case['lookup_id'], owners=owners,
                                    record=receipt, transcript=transcript))
        self.advice_shape = self.pcs.Source(degree, schema.S+2, schema.a0, schema.m, blowup, bytes(32))
        self.constituents = schema.instances(degree)
        self.output, self.output_rows = schema.output_instance(degree, value)

    def abort(self, cause, phase, **details):
        raise VerificationAbort(dict(decision=cause, phase=phase, imports=self.imports, record=None, **details))

    def import_certificate(self, source, packet, original=None):
        scope = 'advice-import' if original is None else f'original-{original}-import'
        failure = None
        try:
            owner = self.observed(scope, self.pcs.verify_certificate, source, packet)
        except ValueError as error:
            failure = str(error)
        observed = self.observations[-1]
        created = observed['created_transcripts']
        need(len(created) <= 1, 'ImportObservation')
        usage = dict(transcript=created[0] if created else self.ref.o.hashes(),
                     non_transcript=observed['non_transcript'])
        if original is None:
            self.imports['advice'] = usage
        else:
            self.imports['originals'].append(usage)
        if failure is not None:
            need(failure in ('ProofShape', 'NoncanonicalField', 'ColumnMismatch', 'RootMismatch'), 'UnclassifiedImportFailure')
            cause = 'Merkle(RootMismatch)' if failure == 'RootMismatch' else failure
            self.abort(cause, 'advice-import' if original is None else 'original-import',
                       **({} if original is None else dict(index=original)))
        return owner

    def statement(self, advice):
        s = self.s
        raw = struct.pack('<BBI4BH4BH', 1, self.d, s.stage, *s.dims, s.spec.mantissa,
                          s.spec.shift, s.spec.bits, self.repetitions, self.blowup,
                          len(s.bound_bytes))+s.bound_bytes+struct.pack('<Q', s.bound)
        for original, event in zip(self.originals, self.ranges, strict=True):
            raw += original.source.bytes()+original.identity
            raw += range_binding(event['identity'], event['owners'])
        raw += advice.source.bytes()+advice.identity+self.pcs.field_bytes([*self.z, self.value])
        need(len(raw) == 457+274*self.repetitions+len(s.bound_bytes)+(s.m+1)*4*self.d, 'StatementLength')
        return raw

    def advice_geometry(self, handle):
        case = Protocol.lookup_case(self, 1, handle)
        return case, self.adapter.geometry(case, [handle])

    def sizes(self):
        s, width = self.s, 4*self.d
        opening = lambda source: self.adapter.size(source, 1)
        suffix = 1+width*(4*(s.dims[0]+s.dims[2])+3)
        suffix += sum(opening(h.source) for h in self.originals)
        return [self.adapter.size(self.advice_shape, 0),
                Protocol.lookup_length(self, self.advice_shape), width*(4*s.m+len(s.ids)),
                opening(self.advice_shape), opening(self.advice_shape),
                width*(4*s.m+len(self.output['ids'])), opening(self.advice_shape), suffix]

    def partition(self, wire):
        sizes = self.sizes()
        need(len(wire) == 34+sum(sizes) and wire[:2] == bytes([1, self.d]), 'ProofShape')
        reader = Reader(wire)
        reader.take(2)
        root = reader.take(32)
        return root, [reader.take(size) for size in sizes]

    def preflight(self, parts, advice):
        case, geometry = self.advice_geometry(advice)
        consumer('Pcs', self.pcs.parse, advice.source, parts[0], self.pcs.counts(advice.source.m, advice.source.blowup)[0])
        consumer('Lookup', self.adapter.parse, case, geometry, parts[1])
        self.arithmetic_read(Reader(parts[2]), len(self.s.ids), zero=True)
        self.arithmetic_read(Reader(parts[5]), len(self.output['ids']))
        for index in (3, 4, 6):
            consumer('Pcs', self.pcs.parse, advice.source, parts[index], self.pcs.counts(advice.source.m, advice.source.blowup)[1])
        # Suffix geometry is known before q. No dummy point or claim is constructed.
        t, width = self.s.dims[0]+self.s.dims[2], 4*self.d
        suffix = Reader(parts[7])
        need(suffix.take(1) == b'\1', 'ProofShape')
        self.pcs.fields(suffix.take(width*(4*t+3)), self.d)
        for original in self.originals:
            source = original.source
            self.pcs.parse(source, suffix.take(self.adapter.size(source, 1)), self.pcs.counts(source.m, source.blowup)[1])
        need(suffix.at == len(suffix.raw), 'ProofShape')

    def matmul_statement(self, point, value):
        h, a, b, c = self.s.dims
        base = self.s.S
        stage, output, coefficient = base+(1 << 22), base+(1 << 21), base+(1 << 28)+2
        statement = dict(field=self.d, id=stage, layout=[(h, 1 << h), (b, 1 << b)], order=0,
            output=dict(id=output, layout=[(h, 1 << h), (a, 1 << a), (c, 1 << c)], point=point, value=value),
            coefficient_id=coefficient, inputs=[o.source.identity for o in self.originals],
            terms=[(self.sc.scalar(1, self.d), [0, 1])],
            coefficient=dict(kind=0, selectors=[point[:h], None], axes=[], source_id=None, values=[], width=None))
        self.ref.stage.encode(statement)
        self.sc.validate(self.ref.stage.instance(statement), self.d)
        frame = (struct.pack('<BBQQQ4B', 2, self.d, stage, output, coefficient, h, a, b, c)
                 + self.pcs.field_bytes([*point, value])
                 + b''.join(o.source.bytes()+o.identity for o in self.originals))
        need(len(frame) == 304+4*self.d*(len(point)+1), 'MatmulStatementLength')
        return statement, frame

    def verify_matmul(self, t, point, value, wire):
        statement, frame = self.matmul_statement(point, value)
        h, a, b, _ = self.s.dims
        reader, width = Reader(wire), 4*self.d
        need(reader.take(1) == b'\1', 'ProofShape')
        proof = dict(rounds=[self.pcs.fields(reader.take(4*width), self.d) for _ in range(h+b)],
                     final=self.pcs.fields(reader.take(3*width), self.d))
        t.absorb(MATMUL, frame)
        reduction = consumer('MatmulStacked', self.ref.stage.verify_reduction, t, statement, proof)
        columns = self.pcs.eq(reduction['point'], self.d)
        outer_points = [point[h:h+a], point[h+a:]]
        records, points, values = [], [], []
        for index, (original, outer, claim) in enumerate(zip(self.originals, outer_points, reduction['claims'], strict=True)):
            identity, signed = claim
            need(identity == original.source.identity, 'SourceRoster')
            rows = self.pcs.eq(outer, self.d)
            total = lambda v: self.pcs.dot([self.sc.scalar(1, self.d)]*len(v), v, self.d)
            raw = self.sc.add(signed, self.sc.mul(self.sc.scalar(128, self.d), self.sc.mul(total(rows), total(columns))))
            opening = reader.take(self.adapter.size(original.source, 1))
            self.observed(f'verify-original-A9-{index}', consumer, 'MatmulPcs', self.pcs.verify_opening,
                          t, identity, original, rows, columns, raw, opening)
            records.append(self.adapter.opening_record(original, identity))
            points.append(outer+reduction['point'])
            values.append(raw)
        need(reader.at == len(wire), 'ProofShape')
        return dict(sc=reduction['sc'], openings=records, points=points, values=values)

    def verify(self, wire, advice_handle=None):
        """Actual closed proof verifier; original matrices and captured C are absent."""
        self.last_verification = dict(phase='preflight', observation_start=len(self.observations))
        self.imports['advice'], self.imports['multiplicities'] = None, None
        count = self.adapter.size(self.advice_shape, 0)
        need(len(wire) >= 34+count, 'NativeRequestProofShape')
        root, packet = wire[2:34], wire[34:34+count]
        source = self.pcs.Source(self.d, self.s.S+2, self.s.a0, self.s.m, self.blowup, root)
        advice = advice_handle
        if advice is None:
            advice = self.import_certificate(source, packet)
        self.imports['multiplicities'] = [None, None]
        try:
            _, parts = self.partition(wire)
            self.preflight(parts, advice)
        except ValueError as error:
            self.abort(str(error), 'multiplicity-import')
        case, geometry = self.advice_geometry(advice)
        case['proof'] = parts[1].hex()
        imported = self.adapter.register(case, geometry)
        self.imports['multiplicities'] = imported['registrations']
        if imported['decision'] != 'accept':
            self.abort(f"Lookup({imported['decision']})", 'multiplicity-import')
        t = self.ref.Transcript(self.public, self.d)
        self.last_verification['transcript'] = t
        self.observed('outer-advice-packet-identity', self.check_advice_packet, source, parts[0], advice)
        self.last_verification['phase'] = 'advice-A5'
        t.absorb(LINEAR, self.statement(advice))
        lookup = self.adapter.consume(case, geometry, t, imported)
        self.last_verification['lookup'] = lookup
        need(lookup['decision'] == 'accept', f"Lookup({lookup['decision']})")
        aggregate = self.aggregate(t)
        packet = self.arithmetic_read(Reader(parts[2]), len(self.s.ids), zero=True)
        zero, _ = consumer('Sumcheck', self.ref.zc.verify_reduction, t, aggregate, packet)
        point, claims = zero['point'], zero['claims']
        need([identity for identity, _, _ in claims] == self.s.ids, 'ArithmeticRoster')
        need(all(p == point for _, p, _ in claims), 'ArithmeticRoster')
        values = [v for _, _, v in claims]
        need(values[0] == public_eq(self.ref, point, self.s.N), 'CoefficientMismatch')
        groups = []
        for index, rows, ids, finals, at in (
                (0, list(range(4)), self.s.ids[1:5], values[1:5], 3),
                (1, list(range(4, self.s.R)), self.s.ids[5:], values[5:], 4)):
            identity, a, b, value, record = self.group(t, index, advice, point, rows, ids, finals)
            self.observed(f'verify-advice-A9-{index}', consumer, 'Pcs', self.pcs.verify_opening,
                          t, identity, advice, a, b, value, parts[at])
            record['opening_record'] = self.adapter.opening_record(advice, identity)
            groups.append(record)
        join_point = list(point)
        join_value = self.sc.add(self.sc.scalar(-(1 << 31), self.d),
            self.pcs.dot([self.sc.scalar(256**k, self.d) for k in range(4)], groups[0]['claims'], self.d))
        packet = self.arithmetic_read(Reader(parts[5]), len(self.output['ids']))
        output = consumer('Sumcheck', self.sc.verify_reduction, t, self.output, packet)
        need([identity for identity, _ in output['claims']] == self.output['ids'], 'ArithmeticRoster')
        need(output['claims'][0][1] == public_eq(self.ref, output['point'], self.s.N, self.z), 'CoefficientMismatch')
        identity, a, b, value, record = self.group(t, 2, advice, output['point'], self.output_rows,
                                                 self.output['ids'][1:], [v for _, v in output['claims'][1:]])
        self.observed('verify-advice-A9-2', consumer, 'Pcs', self.pcs.verify_opening, t, identity, advice, a, b, value, parts[6])
        record['opening_record'] = self.adapter.opening_record(advice, identity)
        groups.append(record)
        matmul = self.verify_matmul(t, join_point, join_value, parts[7])
        rlc = [dict(stage=self.s.stage, phase=phase, field_degree=self.d, count=len(weights), numerator=1, weights=weights)
               for phase, weights in enumerate([self.constraint_weights, *[g['weights'] for g in groups]])]
        need([r['count'] for r in rlc] == [len(self.constituents), 4, self.s.R-4, len(self.output_rows)], 'WeightInventory')
        need(t.draws[b'stele/v0.1/requant/weight'] == sum(r['count'] for r in rlc), 'WeightInventory')
        self.last_verification['phase'] = 'complete'
        return dict(lookup=lookup, zero=zero, output=output, groups=groups, rlc=rlc, matmul=matmul,
                    equality=dict(stage=self.s.stage, aggregate_id=self.s.S+1024, point=join_point,
                                  field_degree=self.d, numerator=self.s.m, family='Sz'),
                    _retained_owners=[self.originals, self.ranges, advice, lookup['_retained_mu_handles']]), t


def decode_request(ref, request):
    """Strict public request parser: reject plaintext, receipts and extra keys."""
    from requant_corpus import keys, integer, array, raw_hex
    keys(request, 'degree stage dims parameters repetitions advice_blowup point value public_hex originals proof_hex following_hex')
    d = integer(request['degree'], 9)
    need(d in (4, 8), 'NativeRequestField')
    dims = [integer(v, 64) for v in array(request['dims'], 4)]
    keys(request['parameters'], 'mantissa shift bits')
    params = request['parameters']
    for v in params.values():
        integer(v, 1 << 32)
    s = Schema(ref, dims, params['mantissa'], params['shift'], params['bits'], integer(request['stage'], 1 << 20))
    field = lambda v: tuple(integer(x, ref.sc.P) for x in array(v, d))
    point = [field(v) for v in array(request['point'], s.m)]
    value = field(request['value'])
    repetitions = integer(request['repetitions'], 3)
    blowup = integer(request['advice_blowup'], 3)
    need(repetitions in (1, 2) and blowup in (1, 2), 'Parameters')
    public = raw_hex(request['public_hex'])
    need(0 < len(public) <= 1 << 20, 'NativeRequestPublic')
    packets = []
    for info in array(request['originals'], 2):
        keys(info, 'source_hex certificate_hex lookup_id mu_ids range_proof_hex')
        raw = raw_hex(info['source_hex'], 105)
        prefix, code = b'stele/v0.1/field-source', b'stele/circle-m31/v1'
        version, degree, identity, ell = struct.unpack_from('<BBQB', raw, len(prefix))
        m, rate = raw[len(prefix)+11+len(code):len(prefix)+13+len(code)]
        source = ref.pcs.Source(degree, identity, ell, m, rate, raw[-32:])
        need(version == 1 and degree == d and source.bytes() == raw, 'NativeRequestSource')
        packets.append(dict(source=source, certificate=raw_hex(info['certificate_hex']),
            lookup_id=integer(info['lookup_id'], 1 << 60),
            mu_ids=[integer(v, 1 << 64) for v in array(info['mu_ids'], repetitions)],
            range_proof=raw_hex(info['range_proof_hex'])))
    wire = raw_hex(request['proof_hex'])
    need(len(wire) <= 64 << 20, 'ResourceLimit')
    following = ref.pcs.fields(raw_hex(request['following_hex'], 12*d), d)
    operation = Operation(ref, s, d, repetitions, packets, point, value, public, blowup)
    return operation, wire, dict(rounds=[following[:2]], final=following[2:])


def project(operation, records, transcript):
    """Serialize actual consumers, including every separately charged import."""
    from requant_corpus import usage
    by_scope = {o['scope']: o for o in operation.observations}
    local = operation.ref.o.hashes()
    outer = [o for o in operation.observations[operation.last_verification['observation_start']:] if o['scope'] == 'outer-advice-packet-identity'
             or o['scope'].startswith(('verify-advice-A9-', 'verify-original-A9-'))]
    need(len(outer) == 6, 'OuterObservation')
    for o in outer+[records['lookup']['usage']]:
        local = {k: v+o['non_transcript'][k] for k, v in local.items()}
    return dict(decision='accept', imports=dict(
        originals=[usage(by_scope[f'original-{i}-import']) for i in range(2)],
        advice=usage(by_scope['advice-import']),
        original_multiplicities=[r['record']['registrations'] for r in operation.ranges],
        multiplicities=records['lookup']['registrations']),
        usage=dict(transcript=transcript.usage.copy(), non_transcript=local),
        original_ranges=[dict(record=r['record']['record'], usage=r['record']['usage']) for r in operation.ranges],
        record=dict(lookup=records['lookup']['record'],
            zero={k: records['zero'][k] for k in ('claims', 'sc')}, output=records['output'],
            groups=[dict(point=g['point'], claims=list(zip(g['rows'], g['ids'], g['claims'])),
                         opening=g['opening_record']) for g in records['groups']],
            rlc=[{k: r[k] for k in ('stage', 'phase', 'field_degree', 'count', 'numerator', 'weights')}
                 for r in records['rlc']], equality=records['equality'], matmul=records['matmul']))


def following_instance(operation):
    sc, d, base = operation.sc, operation.d, operation.s.S
    return dict(id=base+(1 << 29), m=1, ids=[base+(1 << 29)+1],
                terms=[(sc.scalar(1, d), [0])], sum=sc.scalar(3, d))


def verify_request(ref, request):
    try:
        operation, wire, following = decode_request(ref, request)
    except VerificationAbort as error:
        return error.result
    try:
        records, transcript = operation.verify(wire)
    except VerificationAbort as error:
        return error.result
    except ValueError as error:
        # Imports have their own abort records; this is the actual outer prefix.
        attempt = operation.last_verification
        lookup = attempt.get('lookup')
        if lookup is None or lookup['phase'] != 'outer':
            raise
        from requant_corpus import usage
        by_scope = {o['scope']: o for o in operation.observations}
        local = ref.o.hashes()
        outer = [o for o in operation.observations[attempt['observation_start']:]
                 if o['scope'] == 'outer-advice-packet-identity'
                 or o['scope'].startswith(('verify-advice-A9-', 'verify-original-A9-'))]
        for o in outer+[lookup['usage']]:
            local = {k: v+o['non_transcript'][k] for k, v in local.items()}
        return dict(decision=str(error), phase='outer', record=None,
            imports=dict(originals=[usage(by_scope[f'original-{i}-import']) for i in range(2)],
                advice=usage(by_scope['advice-import']),
                original_multiplicities=[r['record']['registrations'] for r in operation.ranges],
                multiplicities=lookup['registrations']),
            usage=dict(transcript=attempt['transcript'].usage.copy(), non_transcript=local))
    result = project(operation, records, transcript)
    sc, d = ref.sc, operation.d
    try:
        next_record = sc.verify_public(transcript, following_instance(operation), following,
                                      [[sc.scalar(1, d), sc.scalar(2, d)]])
    except ValueError as error:
        need(str(error) in ('RoundSumMismatch', 'FinalEvaluationMismatch', 'ClaimMismatch'),
             'UnclassifiedContinuationFailure')
        result['continuation'] = dict(decision=str(error), usage=transcript.usage.copy(), record=None)
        return result
    result['continuation'] = dict(record={k: next_record[k] for k in ('point', 'sc')},
                                  usage=transcript.usage.copy())
    result['continuation']['probe'] = sc.encode(transcript.field(ref.pcs.CHALLENGE)).hex()
    return result


if __name__ == '__main__':
    import argparse
    import json
    from requant_corpus import unique
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-native', required=True, type=Path)
    args = parser.parse_args()
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'Runtime')
    request = json.loads(args.verify_native.read_bytes(), object_pairs_hook=unique)
    with load() as reference:
        print(json.dumps(verify_request(reference, request), sort_keys=True, separators=(',', ':')))
