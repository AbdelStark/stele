"""Draft RFC-0025 passport composition; no signature, evidence or profile admission."""
from dataclasses import dataclass
from struct import pack

from blake3 import blake3

import artifact_codec
from model_codec import encode as encode_model
from numerics import integer
import preparation_execution
import source_codec

SUBJECT=b'stele/v0.1/passport/subject'
EVIDENCE=b'stele/v0.1/passport/evidence'
REGISTRATION=b'stele/v0.1/passport/registration'
SIGN=b'stele/v0.1/passport/sign'
PASSPORT=b'stele/v0.1/passport'
LIMIT=1<<23


@dataclass(frozen=True)
class Reference:
    length: int
    digest: bytes


@dataclass(frozen=True)
class Subject:
    source_identity: bytes
    artifact: Reference
    references: tuple[Reference,...]


@dataclass(frozen=True)
class Evidence:
    proximity: Reference | None
    checkpoint: Reference
    fidelity: Reference


@dataclass(frozen=True)
class Registration:
    registrant: bytes
    timestamp: int
    prior: Reference | None
    keys: tuple[Reference,...]


@dataclass(frozen=True)
class Signature:
    key_id: bytes
    data: Reference


def _digest(raw,reason='Digest'):
    if type(raw) is not bytes or len(raw)!=32:raise ValueError(reason)


def _ref(value):
    if type(value) is not Reference:raise ValueError('Reference')
    integer(value.length,1,2**64-1,'Reference');_digest(value.digest,'Reference')
    return pack('<Q',value.length)+value.digest


def reference(raw):
    if type(raw) is not bytes:raise ValueError('Bytes')
    result=Reference(len(raw),blake3(raw).digest());_ref(result);return result


def check_reference(expected,raw):
    _ref(expected)
    if type(raw) is not bytes:raise ValueError('Bytes')
    if len(raw)!=expected.length:raise ValueError('ReferenceLength')
    if blake3(raw).digest()!=expected.digest:raise ValueError('ReferenceDigest')


def _opt(value):return b'\0' if value is None else b'\1'+_ref(value)
def _blob(raw):return pack('<I',len(raw))+raw
def _hash(raw):return blake3(raw).digest()


def encode_subject(s):
    if type(s) is not Subject:raise ValueError('Parameters')
    if type(s.references) is not tuple or len(s.references)!=11:raise ValueError('References')
    refs=b''.join(_ref(x) for x in s.references)
    if type(s.source_identity) is not bytes or len(s.source_identity)!=33 or s.source_identity[0] not in (0,1):raise ValueError('SourceIdentity')
    if s.source_identity[0]==1 and s.source_identity[1:]!=s.references[5].digest:raise ValueError('SourceIdentity')
    cqis=_hash(preparation_execution.IDENTITY+b''.join(x.digest for x in s.references[:4]))
    return SUBJECT+cqis+s.source_identity+_ref(s.artifact)+refs


def _evidence(subject_id,e):
    if type(e) is not Evidence:raise ValueError('Parameters')
    return EVIDENCE+subject_id+_opt(e.proximity)+_ref(e.checkpoint)+_ref(e.fidelity)


def _registration(subject_id,evidence_id,r):
    if type(r) is not Registration:raise ValueError('Parameters')
    _digest(r.registrant);integer(r.timestamp,0,2**64-1,'Timestamp')
    if type(r.keys) is not tuple or not 1<=len(r.keys)<=65535:raise ValueError('KeyCount')
    keys=b''.join(_ref(k) for k in r.keys)
    if any(a.digest>=b.digest for a,b in zip(r.keys,r.keys[1:])):raise ValueError('KeyOrder')
    return REGISTRATION+subject_id+evidence_id+r.registrant+pack('<Q',r.timestamp)+_opt(r.prior)+pack('<H',len(r.keys))+keys


def _signatures(r,signatures):
    if type(signatures) is not tuple or len(signatures)!=len(r.keys):raise ValueError('Signers')
    parts=[]
    for key,s in zip(r.keys,signatures):
        if type(s) is not Signature or type(s.key_id) is not bytes or s.key_id!=key.digest:raise ValueError('Signers')
        parts.append(s.key_id+_ref(s.data))
    return pack('<H',len(signatures))+b''.join(parts)


def _parts(s,e,r):
    subject=encode_subject(s);sid=_hash(subject);evidence=_evidence(sid,e)
    return subject,evidence,_registration(sid,_hash(evidence),r)


def message(s,e,r):return SIGN+b''.join(_hash(x) for x in _parts(s,e,r))


def encode(s,e,r,signatures):
    parts=_parts(s,e,r)+(_signatures(r,signatures),)
    raw=PASSPORT+b''.join(_blob(x) for x in parts)
    if len(raw)>LIMIT:raise ValueError('Capacity')
    return raw


def root(s,e,r,signatures):return _hash(encode(s,e,r,signatures))


def verify(s,e,r,signatures,raw):
    if type(raw) is not bytes or len(raw)>LIMIT:raise ValueError('Capacity')
    if raw!=encode(s,e,r,signatures):raise ValueError('Passport')


class _Reader:
    def __init__(self,raw):self.raw,self.pos=raw,0
    def take(self,n):
        if n>len(self.raw)-self.pos:raise ValueError('Encoding')
        value=self.raw[self.pos:self.pos+n];self.pos+=n;return value
    def number(self,n):return int.from_bytes(self.take(n),'little')
    def blob(self):return self.take(self.number(4))
    def prefix(self,expected):
        if self.take(len(expected))!=expected:raise ValueError('Encoding')
    def reference(self):return Reference(self.number(8),self.take(32))
    def optional(self):
        tag=self.number(1)
        if tag==0:return None
        if tag==1:return self.reference()
        raise ValueError('Optional')
    def count(self,n,width):
        if len(self.raw)-self.pos!=n*width:raise ValueError('Encoding')
    def end(self):self.count(0,1)


def decode(raw):
    if type(raw) is not bytes or len(raw)>LIMIT:raise ValueError('Capacity')
    reader=_Reader(raw);reader.prefix(PASSPORT);parts=tuple(reader.blob() for _ in range(4));reader.end()
    sr,er,rr,ss=parts
    if len(sr)!=572:raise ValueError('Encoding')
    reader=_Reader(sr);reader.prefix(SUBJECT);cqis=reader.take(32)
    s=Subject(reader.take(33),reader.reference(),tuple(reader.reference() for _ in range(11)));reader.end()
    if cqis!=encode_subject(s)[len(SUBJECT):len(SUBJECT)+32]:raise ValueError('NumericIdentity')
    sid=_hash(sr);reader=_Reader(er);reader.prefix(EVIDENCE)
    if reader.take(32)!=sid:raise ValueError('EvidenceSubject')
    e=Evidence(reader.optional(),reader.reference(),reader.reference());reader.end();_evidence(sid,e)
    eid=_hash(er);reader=_Reader(rr);reader.prefix(REGISTRATION)
    if reader.take(32)!=sid:raise ValueError('RegistrationSubject')
    if reader.take(32)!=eid:raise ValueError('RegistrationEvidence')
    registrant,timestamp,prior=reader.take(32),reader.number(8),reader.optional();count=reader.number(2)
    if not 1<=count<=65535:raise ValueError('KeyCount')
    reader.count(count,40);r=Registration(registrant,timestamp,prior,tuple(reader.reference() for _ in range(count)));reader.end();_registration(sid,eid,r)
    reader=_Reader(ss)
    if reader.number(2)!=len(r.keys):raise ValueError('Signers')
    reader.count(len(r.keys),72);signatures=tuple(Signature(reader.take(32),reader.reference()) for _ in r.keys);reader.end();_signatures(r,signatures)
    return s,e,r,signatures


def subject_from_files(model,mapping,layout,source,assets,files,registry,bounds,tail):
    """Validate numerical/source fields only; tail references grant no child admission."""
    if type(tail) is not tuple or len(tail)!=3:raise ValueError('References')
    for value in tail:_ref(value)
    prepared=preparation_execution.prepare(model,mapping,layout,source,assets,files)
    converted=prepared.conversion
    preparation_execution.identity(model,converted.scales,registry,bounds)
    values=(encode_model(model),converted.scales,registry,bounds,artifact_codec.encode_preparation(model,mapping),
            source_codec.encode_source(source),source_codec.encode_assets(assets),prepared.source_config)
    s=Subject(converted.source_identity,Reference(converted.length,converted.digest),tuple(reference(x) for x in values)+tail)
    encode_subject(s);return s
