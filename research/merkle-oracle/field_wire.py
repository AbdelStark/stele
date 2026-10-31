"""Draft RFC-0010 A9 byte oracle. Research only; imports no native implementation."""
from dataclasses import dataclass
from pathlib import Path
import struct
import sys
from blake3 import blake3

ROOT = Path(__file__).resolve().parents[1]
for folder in ('sumcheck', 'circle-code', 'merkle', 'transcript'):
    sys.path.insert(0, str(ROOT / folder))
import check_sumcheck as sc
import check_circle as circle
import check_merkle as merkle
from check_transcript import sample, INITIAL, PUBLIC, INSTANCE, ROUND, FINAL, CHALLENGE
from native_policy import counts, decode_index

P, scalar, encode = sc.P, sc.scalar, sc.encode
PREFIX = b'stele/v0.1/pcs/'
WEIGHT, CERT_ROW, CERT_COLUMN, CERT_COLUMNS, OPEN, OPEN_ROW, OPEN_COLUMN, OPEN_COLUMNS, SOURCES = (
    PREFIX+name for name in (b'certificate-weight', b'certificate-row', b'certificate-column',
    b'certificate-columns', b'opening', b'opening-row', b'opening-column', b'opening-columns', b'sources'))
ABSORBS = (INSTANCE, ROUND, FINAL, CERT_ROW, CERT_COLUMNS, OPEN, OPEN_ROW, OPEN_COLUMNS, SOURCES)
CHALLENGES = (CHALLENGE, WEIGHT, CERT_COLUMN, OPEN_COLUMN)
rejects, flip = merkle.rejects, merkle.flip


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def frame(state, tag, label, payload):
    return state+bytes([tag])+struct.pack('<I', len(label))+label+struct.pack('<Q', len(payload))+payload


class Transcript:
    def __init__(self, public, degree):
        require(public and degree in (4, 8), 'InvalidTranscript')
        self.degree = degree
        self.state = blake3(frame(blake3(INITIAL).digest(), 0, PUBLIC, public)).digest()

    def absorb(self, label, message):
        require(label in ABSORBS, 'InvalidAbsorbLabel')
        self.state = blake3(frame(self.state, 0, label, message)).digest()

    def challenge(self, label=CHALLENGE):
        require(label in CHALLENGES, 'InvalidChallengeLabel')
        old = self.state
        raw = blake3(frame(old, 1, label, bytes([self.degree]))).digest(length=256)
        value, consumed = sample(raw, self.degree)
        payload = bytes([self.degree])+struct.pack('<I', consumed)+value
        self.state = blake3(frame(old, 2, label, payload)).digest()
        return value, consumed

    def field(self, label):
        return struct.unpack('<'+'I'*self.degree, self.challenge(label)[0])

    def column(self, label, size):
        require(label in (CERT_COLUMN, OPEN_COLUMN), 'InvalidChallengeLabel')
        require(type(size) is int and 2 <= size <= 2**30 and not size & (size-1), 'InvalidColumnDomain')
        for _ in range(64):
            index = decode_index(self.field(label)[0], size, P)
            if index is not None:
                return index
        raise ValueError('ColumnSamplingExhausted')


def field_bytes(values):
    return b''.join(map(encode, values))


def fields(raw, degree):
    require(len(raw) % (4*degree) == 0, 'ProofShape')
    limbs = list(struct.iter_unpack('<'+'I'*degree, raw))
    require(all(x < P for value in limbs for x in value), 'NoncanonicalField')
    return limbs


def dot(a, b, degree):
    require(len(a) == len(b), 'ProofShape')
    result = scalar(0, degree)
    for x, y in zip(a, b):
        result = sc.add(result, sc.mul(x, y))
    return result


def eq(point, degree):
    result = [scalar(1, degree)]
    for coordinate in point:
        left = sc.add(scalar(1, degree), sc.neg(coordinate))
        result = [sc.mul(weight, factor) for weight in result for factor in (left, coordinate)]
    return result


def row(matrix, a, degree):
    return [dot(a, [scalar(x, degree) for x in column], degree) for column in zip(*matrix)]


def extension_encode(values, blowup):
    # The Circle map is base-linear: evaluate every extension coefficient independently.
    return list(zip(*(circle.encode(list(limbs), blowup) for limbs in zip(*values))))


@dataclass(frozen=True)
class Source:
    degree: int
    identity: int
    ell: int
    m: int
    blowup: int
    root: bytes

    def bytes(self):
        require(self.degree in (4, 8) and type(self.identity) is int
                and 0 <= self.identity < 2**64 and type(self.ell) is int
                and 0 <= self.ell <= 30 and len(self.root) == 32, 'UnsupportedSource')
        counts(self.m, self.blowup)
        code = b'stele/circle-m31/v1'+bytes([self.m, self.blowup])
        return (b'stele/v0.1/field-source'+struct.pack('<BBQB', 1, self.degree, self.identity, self.ell)
                +code+struct.pack('<QQBB', 1 << self.ell, 1 << self.m, 0, 1)+self.root)

    def tree(self):
        self.bytes()
        return merkle.Tree(0, self.identity, 1 << (self.m+self.blowup), 4 << self.ell)


def commit(matrix, ell, m, blowup, degree, identity):
    source = Source(degree, identity, ell, m, blowup, bytes(32))
    tree = source.tree()
    require(len(matrix) == 1 << ell and all(len(r) == 1 << m for r in matrix), 'ProofShape')
    require(all(type(x) is int and 0 <= x < P for r in matrix for x in r), 'NoncanonicalField')
    encoded = [circle.encode(r, blowup) for r in matrix]
    payloads = [struct.pack('<'+'I'*len(matrix), *column) for column in zip(*encoded)]
    levels = merkle.build(tree, payloads)
    source = Source(degree, identity, ell, m, blowup, levels[-1][0])
    return source, (matrix, payloads, levels)


def responses(transcript, source, witness, label, count):
    _, payloads, levels = witness
    tree = source.tree()
    out = bytearray()
    for _ in range(count):
        index = transcript.column(label, tree.count)
        out.extend(payloads[index])
        out.extend(b''.join(merkle.path(levels, index)))
    return bytes(out)


def parse(source, proof, count):
    tree = source.tree()
    row_end = 1+4*source.degree*(1 << source.m)
    response_size = tree.width+32*tree.height()
    require(len(proof) == row_end+count*response_size and proof[:1] == b'\1', 'ProofShape')
    return fields(proof[1:row_end], source.degree), proof[row_end:]


def verify_responses(transcript, source, a, u, block, label, count):
    tree = source.tree()
    stride = tree.width+32*tree.height()
    expected = extension_encode(u, source.blowup)
    for q in range(count):
        index = transcript.column(label, tree.count)
        response = block[q*stride:(q+1)*stride]
        payload = response[:tree.width]
        siblings = [response[i:i+32] for i in range(tree.width, stride, 32)]
        merkle.verify(tree, source.root, index, payload, siblings)
        column = [scalar(x[0], source.degree) for x in fields(payload, 1)]
        require(expected[index] == dot(a, column, source.degree), 'ColumnMismatch')


def certificate_transcript(source):
    transcript = Transcript(b'stele/v0.1/pcs-certificate/public'+source.bytes(), source.degree)
    return transcript, eq([transcript.field(WEIGHT) for _ in range(source.ell)], source.degree)


def certify(source, witness):
    transcript, a = certificate_transcript(source)
    t = row(witness[0], a, source.degree)
    transcript.absorb(CERT_ROW, field_bytes(t))
    block = responses(transcript, source, witness, CERT_COLUMN, counts(source.m, source.blowup)[0])
    transcript.absorb(CERT_COLUMNS, block)
    return b'\1'+field_bytes(t)+block


_VERIFIED = object()


class Verified:
    """Research handle; Python reflection is not a native opacity guarantee."""
    def __init__(self, token, source, identity):
        require(token is _VERIFIED, 'CertificateContext')
        self.source, self.identity = source, identity


def verify_certificate(source, proof):
    count = counts(source.m, source.blowup)[0]
    t, block = parse(source, proof, count)
    transcript, a = certificate_transcript(source)
    transcript.absorb(CERT_ROW, field_bytes(t))
    verify_responses(transcript, source, a, t, block, CERT_COLUMN, count)
    transcript.absorb(CERT_COLUMNS, block)
    public = source.bytes()
    identity = blake3(b'stele/v0.1/pcs-certificate/id'+struct.pack('<Q', len(public))
                      +public+struct.pack('<Q', len(proof))+proof).digest()
    return Verified(_VERIFIED, source, identity)


def opening_instance(transcript, identity, verified, a, b, value):
    require(isinstance(verified, Verified), 'CertificateContext')
    source = verified.source
    require(transcript.degree == source.degree, 'CertificateContext')
    require(0 <= identity < 2**64, 'ProofShape')
    require(len(a) == 1 << source.ell and len(b) == 1 << source.m, 'FunctionalShape')
    values = list(a)+list(b)+[value]
    require(all(len(v) == source.degree and all(0 <= x < P for x in v) for v in values), 'NoncanonicalField')
    transcript.absorb(OPEN, struct.pack('<Q', identity)+source.bytes()+verified.identity
                      +field_bytes(a)+field_bytes(b)+encode(value))


def open_functional(transcript, identity, verified, witness, a, b, value):
    opening_instance(transcript, identity, verified, a, b, value)
    source = verified.source
    u = row(witness[0], a, source.degree)
    require(dot(u, b, source.degree) == value, 'ValueMismatch')
    transcript.absorb(OPEN_ROW, field_bytes(u))
    block = responses(transcript, source, witness, OPEN_COLUMN, counts(source.m, source.blowup)[1])
    transcript.absorb(OPEN_COLUMNS, block)
    return b'\1'+field_bytes(u)+block


def verify_opening(transcript, identity, verified, a, b, value, proof):
    require(isinstance(verified, Verified), 'CertificateContext')
    source = verified.source
    count = counts(source.m, source.blowup)[1]
    u, block = parse(source, proof, count)
    opening_instance(transcript, identity, verified, a, b, value)
    transcript.absorb(OPEN_ROW, field_bytes(u))
    require(dot(u, b, source.degree) == value, 'ValueMismatch')
    verify_responses(transcript, source, a, u, block, OPEN_COLUMN, count)
    transcript.absorb(OPEN_COLUMNS, block)


def bind_sources(transcript, instance, certificates):
    sc.validate(instance, transcript.degree)
    require(len(certificates) == len(instance['ids']) and all(
        isinstance(cert, Verified) and cert.source.identity == identity
        and cert.source.degree == transcript.degree and cert.source.ell+cert.source.m == instance['m']
        for identity, cert in zip(instance['ids'], certificates)), 'SourceRoster')
    transcript.absorb(SOURCES, struct.pack('<QI', instance['id'], len(certificates))
                      +b''.join(cert.source.bytes()+cert.identity for cert in certificates))
