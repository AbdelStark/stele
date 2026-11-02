"""RFC0023 batched reference composition. No native code or plaintext acceptance."""
import hashlib
import struct
from reference import STATEMENT, CONSTRAINTS, CLAIMS, WEIGHT
from lookup_reference import make
from requant_schema import Schema as Layout
from time import perf_counter_ns


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def public_eq(ref, point, real, selector=None):
    d = len(point[0]) if point else ref.degree
    one = ref.sc.scalar(1, d)
    pairs = []
    for k, r in enumerate(point):
        pair = [ref.sc.add(one, ref.sc.neg(r)), r]
        if selector is not None:
            z = selector[k]
            pair = [ref.sc.mul(pair[0], ref.sc.add(one, ref.sc.neg(z))), ref.sc.mul(pair[1], z)]
        pairs.append(pair)
    return ref.public.bounded(pairs, real, d)


class Schema(Layout):
    """Use the existing independent static compiler, with fixed operation ids."""
    def __init__(self, ref, mantissa, shift, bits, n, stage):
        super().__init__(mantissa, shift, bits)
        need(type(n) is int and n >= 1 and type(stage) is int and 1 <= stage < 2**20, 'Parameters')
        self.ref, self.n, self.stage = ref, n, stage
        self.m = (n-1).bit_length()
        self.N, self.S = 1 << self.m, stage << 40
        need((4+self.R)*self.N <= 4096, 'ResourceLimit')
        self.ids = [self.S+(1 << 28)]+[self.S+(1 << 24)+k for k in range(4+self.R)]
        self.constraints = super().constraints()

    def instances(self, d):
        sc = self.ref.sc
        return [dict(id=self.S+4096+j, m=self.m, ids=self.ids,
                     terms=[(sc.scalar(c, d), list(fs)) for c, fs in terms], sum=sc.scalar(0, d))
                for j, (_, terms) in enumerate(self.constraints)]

    def output_instance(self, d, value):
        sc = self.ref.sc
        rows = [0, *self.blocks['q'].rows]
        ids = [self.S+(1 << 28)+1]+[self.ids[5+row] for row in rows]
        terms = []
        for k in range(len(self.blocks['q'].rows)):
            terms += [(sc.scalar(256**k, d), [0, 2+k]), (sc.scalar(-2*256**k, d), [0, 1, 2+k])]
        return dict(id=self.S+2048, m=self.m, ids=ids, terms=terms, sum=value), rows


class Reader:
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def take(self, count):
        need(type(count) is int and 0 <= count <= len(self.raw)-self.at, 'ProofShape')
        start, self.at = self.at, self.at+count
        return self.raw[start:self.at]


class Protocol:
    def __init__(self, ref, schema, degree, repetitions, input_packet, z, value, public, blowup=1):
        self.ref, self.s, self.d, self.repetitions = ref, schema, degree, repetitions
        ref.degree = degree
        self.pcs, self.sc = ref.pcs, ref.sc
        self.adapter = make(ref.o)
        self.observations = []
        self.z, self.value, self.public = z, value, public
        need(blowup in (1, 2), 'AdviceBlowup')
        self.blowup = blowup
        self.input_packet = input_packet
        self.input = self.observed('input-registration', self.pcs.verify_certificate,
                                   input_packet['source'], input_packet['certificate'])
        source = self.input.source
        need(source.degree == degree and source.ell == 2 and source.m == schema.m, 'InputContext')
        need(2 <= source.identity < 2**64 and not schema.S <= source.identity < schema.S+(1 << 40), 'InputIdentity')
        need(degree in (4, 8) and repetitions in (1, 2) and len(z) == schema.m, 'Parameters')
        self.pcs.fields(self.pcs.field_bytes([*z, value]), degree)
        self.advice_shape = self.pcs.Source(degree, schema.S+2, schema.a0, schema.m, blowup, bytes(32))
        self.constituents = schema.instances(degree)
        self.output, self.output_rows = schema.output_instance(degree, value)

    def observed(self, label, call, *args):
        local, start = self.ref.o.hashes(), len(self.ref.o.CREATED)
        observation = dict(scope=label, outcome='failure', non_transcript=local)
        self.observations.append(observation)
        start_ns = perf_counter_ns()
        try:
            with self.ref.o.local_hashes(local):
                result = call(*args)
        finally:
            observation['elapsed_ns'] = perf_counter_ns()-start_ns
            observation['created_transcripts'] = [t.usage.copy() for t in self.ref.o.CREATED[start:]]
        observation['outcome'] = 'success'
        return result

    def statement(self, advice):
        s = self.s
        raw = struct.pack('<BBIQBHBBBBH', 1, self.d, s.stage, s.n, s.m,
                          s.spec.mantissa, s.spec.shift, s.spec.bits, self.repetitions,
                          advice.source.blowup, len(s.bound_bytes))+s.bound_bytes
        raw += self.input.source.bytes()+self.input.identity+advice.source.bytes()+advice.identity
        raw += self.pcs.field_bytes([*self.z, self.value])
        assert len(raw) == 297+len(s.bound_bytes)+(s.m+1)*4*self.d
        return raw

    def constraints_frame(self):
        s = self.s
        out = struct.pack('<IBI', s.stage, s.m, len(s.ids))
        out += b''.join(struct.pack('<Q', v) for v in s.ids)+struct.pack('<I', len(self.constituents))
        for i in self.constituents:
            out += struct.pack('<QBI', i['id'], self.sc.degree(i), len(i['terms']))
            for c, fs in i['terms']:
                out += self.sc.encode(c)+bytes([len(fs)])+b''.join(struct.pack('<I', x) for x in fs)
        return out

    def aggregate(self, t):
        t.absorb(CONSTRAINTS, self.constraints_frame())
        terms, weights = [], []
        for instance in self.constituents:
            gamma = t.field(WEIGHT)
            weights.append(gamma)
            terms += [(self.sc.mul(gamma, c), fs) for c, fs in instance['terms']]
        i = dict(id=self.s.S+1024, m=self.s.m, k=0, ids=self.s.ids,
                 terms=terms, sum=self.sc.scalar(0, self.d))
        assert self.sc.degree(i) == 3 and len(weights) == len(self.constituents)
        self.constraint_weights = weights
        return i

    def lookup_case(self, group, handle, message=None):
        s, source = self.s, handle.source
        total_bits = source.ell+source.m
        original = dict(id=source.identity, ell=source.ell, blowup=source.blowup)
        if message is not None:
            original['message'] = [v for row in message for v in row]
        return dict(name=f'requant-byte-{group}', degree=self.d, m=total_bits,
                    b=min(total_bits, 30), lookup_id=s.S//16+8+group,
                    table=dict(name='range_8', version=1, params_hex=''),
                    selector=[1]*(1 << total_bits), originals=[original],
                    multiplicities=[dict(id=s.S+16+2*group+k, ell=0, blowup=1)
                                    for k in range(self.repetitions)])

    def geometry(self, group, handle):
        case = self.lookup_case(group, handle)
        return case, self.adapter.geometry(case, [handle])

    def lookup_length(self, source):
        # Exact A5 range_8 geometry: 256 rows, one column, ell(mu)=0,
        # hence one full piece and no tail. These are size metadata, not handles.
        mu = self.pcs.Source(self.d, self.s.S+16, 0, 8+(self.d.bit_length()-1), 1, bytes(32))
        m = source.ell+source.m
        tree = lambda k: 4*self.d*(2+2*k*k+3*k)
        return 2+self.repetitions*(32+self.adapter.size(mu, 0)+tree(m)+tree(8)
                    +4*self.d*(4*m+3)+self.adapter.size(source, 1)
                    +4*self.d+self.adapter.size(mu, 1))

    def expected_length(self, advice_source):
        return (2+32+self.adapter.size(advice_source, 0)
                +sum(self.lookup_length(source) for source in (self.input.source, advice_source))
                +4*self.d*(8*self.s.m+7+self.s.R+len(self.s.blocks['q'].rows))
                +self.adapter.size(self.input.source, 1)+2*self.adapter.size(advice_source, 1))

    def group(self, t, index, handle, point, rows, ids, values):
        need(len(rows) == len(ids) == len(values) and len(set(rows)) == len(rows), 'GroupShape')
        need(len(point) == self.s.m, 'GroupPoint')
        frame = struct.pack('<IB', self.s.stage, index)+handle.source.bytes()+handle.identity
        frame += struct.pack('<IB', len(rows), self.s.m)+self.pcs.field_bytes(point)
        for row, identity, value in zip(rows, ids, values):
            frame += struct.pack('<IQ', row, identity)+self.sc.encode(value)
        t.absorb(CLAIMS, frame)
        weights = [t.field(WEIGHT) for _ in rows]
        a = [self.sc.scalar(0, self.d)]*(1 << handle.source.ell)
        for row, weight in zip(rows, weights):
            need(0 <= row < len(a), 'GroupRow')
            a[row] = weight
        b = self.pcs.eq(point, self.d)
        value = self.pcs.dot(weights, values, self.d)
        identity = self.s.S+3072+index
        record = dict(group=index, rows=rows, ids=ids, point=point, claims=values,
                      weights=weights, source=handle.source.bytes().hex(),
                      certificate=handle.identity.hex(), opening_id=identity,
                      frame_sha256=hashlib.sha256(frame).hexdigest())
        return identity, a, b, value, record


    def arithmetic_read(self, reader, count, zero=False):
        rows = [self.pcs.fields(reader.take(4*self.d*4), self.d) for _ in range(self.s.m)]
        final = self.pcs.fields(reader.take(4*self.d*count), self.d)
        return dict(skip=[], rounds=rows, final=[[v] for v in final]) if zero else dict(rounds=rows, final=final)

    def arithmetic_offsets(self):
        start = (2+32+self.adapter.size(self.advice_shape, 0)
                 +self.lookup_length(self.input.source)+self.lookup_length(self.advice_shape))
        output = (start+4*self.d*(4*self.s.m+len(self.s.ids))
                  +self.adapter.size(self.input.source, 1)+self.adapter.size(self.advice_shape, 1))
        return start, output

    def preflight(self, wire):
        need(len(wire) == self.expected_length(self.advice_shape), 'ProofShape')
        need(wire[:2] == bytes([1, self.d]), 'ProofShape')
        zero_at, output_at = self.arithmetic_offsets()
        reader = Reader(wire)
        reader.at = zero_at
        self.arithmetic_read(reader, len(self.s.ids), zero=True)
        reader.at = output_at
        self.arithmetic_read(reader, len(self.output['ids']))

    def preflight_children(self, wire, advice):
        # After standalone advice import, but before an outer transcript exists.
        # A9 parse checks only header/length/canonical u. Column payloads remain
        # raw until each actual Merkle verifier authenticates them.
        reader = Reader(wire)
        reader.at = 2+32+self.adapter.size(advice.source, 0)
        for group, handle in enumerate((self.input, advice)):
            case, geometry = self.geometry(group, handle)
            self.adapter.parse(case, geometry, reader.take(self.adapter.proof_size(case, geometry)))
        self.arithmetic_read(reader, len(self.s.ids), zero=True)
        for handle in (self.input, advice):
            self.pcs.parse(handle.source, reader.take(self.adapter.size(handle.source, 1)),
                           self.pcs.counts(handle.source.m, handle.source.blowup)[1])
        self.arithmetic_read(reader, len(self.output['ids']))
        self.pcs.parse(advice.source, reader.take(self.adapter.size(advice.source, 1)),
                       self.pcs.counts(advice.source.m, advice.source.blowup)[1])
        need(reader.at == len(wire), 'ProofShape')


    def check_advice_packet(self, source, certificate, handle):
        need(isinstance(handle, self.pcs.Verified), 'CertificateContext')
        need(handle.source.bytes() == source.bytes(), 'CertificateContext')
        public = source.bytes()
        identity = self.pcs.blake3(b'stele/v0.1/pcs-certificate/id'
                    +struct.pack('<Q', len(public))+public
                    +struct.pack('<Q', len(certificate))+certificate).digest()
        need(identity == handle.identity, 'CertificateIdentity')


    def verify(self, wire, advice_handle=None):
        self.last_verification = dict(phase='preflight', transcript=None)
        self.preflight(wire)
        reader = Reader(wire)
        need(reader.take(2) == bytes([1, self.d]), 'ProofShape')
        source = self.pcs.Source(self.d, self.s.S+2, self.s.a0, self.s.m, self.blowup, reader.take(32))
        # Size preflight is independent of a genuine registration result.
        need(len(wire) == self.expected_length(source), 'ProofShape')
        certificate = reader.take(self.adapter.size(source, 0))
        self.last_verification['phase'] = 'advice-registration'
        advice = advice_handle
        if advice is None:
            advice = self.observed('advice-import-verifier', self.pcs.verify_certificate, source, certificate)
        self.last_verification['phase'] = 'outer-identities'
        need(self.input.source.bytes() == self.input_packet['source'].bytes(), 'CertificateContext')
        self.observed('outer-advice-packet-identity', self.check_advice_packet, source, certificate, advice)
        self.last_verification['phase'] = 'preflight-children'
        self.preflight_children(wire, advice)
        t = self.ref.Transcript(self.public, self.d)
        self.last_verification['transcript'] = t
        t.absorb(STATEMENT, self.statement(advice))
        records = dict(lookups=[], groups=[], _retained_sources=[self.input, advice])
        self.last_verification['records'] = records
        for group, handle in enumerate((self.input, advice)):
            self.last_verification['phase'] = f'lookup-{group}'
            case, geometry = self.geometry(group, handle)
            assert self.lookup_length(handle.source) == self.adapter.proof_size(case, geometry)
            case['proof'] = reader.take(self.adapter.proof_size(case, geometry)).hex()
            receipt = self.adapter.verify(case, geometry, t)
            records['lookups'].append(receipt)
            need(receipt['decision'] == 'accept', f"LookupVerifier:{receipt['decision']}")
        self.last_verification['phase'] = 'aggregate-A3'
        i = self.aggregate(t)
        proof = self.arithmetic_read(reader, len(self.s.ids), zero=True)
        reduction, _ = self.ref.zc.verify_reduction(t, i, proof)
        assert [r['numerator'] for r in reduction['sc']] == [self.s.m, 0, 3*self.s.m]
        point = reduction['point']
        claims = reduction['claims']
        need([identity for identity, _, _ in claims] == self.s.ids, 'ArithmeticRoster')
        need(all(p == point for _, p, _ in claims), 'ArithmeticPoint')
        values = [v for _, _, v in claims]
        need(values[0] == public_eq(self.ref, point, self.s.n), 'CoefficientMismatch')
        records['zero'] = reduction
        for index, handle, rows, ids, finals in (
                (0, self.input, list(range(4)), self.s.ids[1:5], values[1:5]),
                (1, advice, list(range(self.s.R)), self.s.ids[5:], values[5:])):
            self.last_verification['phase'] = f'A9-group-{index}'
            identity, a, b, value, record = self.group(t, index, handle, point, rows, ids, finals)
            opening = reader.take(self.adapter.size(handle.source, 1))
            record.update(closed=False, opening_sha256=hashlib.sha256(opening).hexdigest())
            records['groups'].append(record)
            self.observed(f'verify-A9-{index}', self.pcs.verify_opening,
                          t, identity, handle, a, b, value, opening)
            record.update(closed=True, queries=self.pcs.counts(handle.source.m, handle.source.blowup)[1])
            record['opening_record'] = self.adapter.opening_record(handle, identity)
        self.last_verification['phase'] = 'output-A1'
        proof = self.arithmetic_read(reader, len(self.output['ids']))
        reduction = self.sc.verify_reduction(t, self.output, proof)
        assert reduction['sc']['degree'] == 3 and reduction['sc']['numerator'] == 3*self.s.m
        point, claims = reduction['point'], reduction['claims']
        need([identity for identity, _ in claims] == self.output['ids'], 'OutputRoster')
        need(claims[0][1] == public_eq(self.ref, point, self.s.N, self.z), 'CoefficientMismatch')
        records['output'] = reduction
        identity, a, b, value, record = self.group(t, 2, advice, point, self.output_rows,
                                                 self.output['ids'][1:], [v for _, v in claims[1:]])
        self.last_verification['phase'] = 'A9-group-2'
        opening = reader.take(self.adapter.size(advice.source, 1))
        record.update(closed=False, opening_sha256=hashlib.sha256(opening).hexdigest())
        records['groups'].append(record)
        self.observed('verify-A9-2', self.pcs.verify_opening, t, identity, advice, a, b, value,
                       opening)
        record.update(closed=True, queries=self.pcs.counts(advice.source.m, advice.source.blowup)[1])
        record['opening_record'] = self.adapter.opening_record(advice, identity)
        need(reader.at == len(wire), 'ProofShape')
        records['rlc'] = [dict(kind='constraints', stage=self.s.stage, phase=0,
                              field_degree=self.d, count=len(self.constituents), numerator=1)]
        records['rlc'] += [dict(kind=f'group-{r["group"]}', stage=self.s.stage, phase=r['group']+1,
                               field_degree=self.d, count=len(r['rows']), numerator=1)
                           for r in records['groups']]
        assert [r['count'] for r in records['rlc']] == [len(self.constituents), 4, self.s.R, 1+len(self.s.blocks['q'].rows)]
        assert [r['phase'] for r in records['rlc']] == [0, 1, 2, 3]
        assert all(r['stage'] == self.s.stage and r['field_degree'] == self.d and r['numerator'] == 1
                   for r in records['rlc'])
        expected_draws = len(self.constituents)+4+self.s.R+1+len(self.s.blocks['q'].rows)
        need(t.draws[WEIGHT] == expected_draws, 'WeightInventory')
        records['rlc'][0]['weights'] = self.constraint_weights
        for r, group in zip(records['rlc'][1:], records['groups']):
            r['weights'] = group['weights']
        records['weights'] = expected_draws
        records['usage'] = t.usage.copy()
        records['wire_bytes'] = len(wire)
        records['wire_sha256'] = hashlib.sha256(wire).hexdigest()
        self.last_verification['phase'] = 'complete'
        return records, t
