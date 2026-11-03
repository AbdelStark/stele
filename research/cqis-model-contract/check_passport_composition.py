"""Draft RFC-0025 outer composition; references are not cryptographic admission."""
from dataclasses import replace
from fractions import Fraction
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3

from check_arithmetic_bounds import rejects
from check_artifact_codec import preparation
from check_model_codec import oracle as model_frame
from check_preparation_execution import case
from check_source_architecture import architecture_frame,map_frame
from check_source_codec import source_frame,assets_frame
from check_source_conversion import oracle as convert
import bound_collection
import registry_codec
import scales_codec
import passport_composition as c
import public_input
from request_bounds import Request


def ref(r):return pack('<Q',r.length)+r.digest
def opt(r):return b'\0' if r is None else b'\1'+ref(r)
def blob(raw):return pack('<I',len(raw))+raw
def digest(raw):return blake3(raw).digest()
def reference(raw):return c.Reference(len(raw),digest(raw))


def subject_wire(s):
    numeric=digest(b'stele/v0.1/cqis/identity'+b''.join(r.digest for r in s.references[:4]))
    return b'stele/v0.1/passport/subject'+numeric+s.source_identity+ref(s.artifact)+b''.join(ref(r) for r in s.references)


def sections(s,e,r,signatures):
    subject=subject_wire(s);sid=digest(subject)
    evidence=b'stele/v0.1/passport/evidence'+sid+opt(e.proximity)+ref(e.checkpoint)+ref(e.fidelity)
    registration=(b'stele/v0.1/passport/registration'+sid+digest(evidence)+r.registrant+pack('<Q',r.timestamp)
                  +opt(r.prior)+pack('<H',len(r.keys))+b''.join(ref(k) for k in r.keys))
    signed=pack('<H',len(signatures))+b''.join(x.key_id+ref(x.data) for x in signatures)
    return subject,evidence,registration,signed


def wire(s,e,r,signatures):return b'stele/v0.1/passport'+b''.join(blob(x) for x in sections(s,e,r,signatures))
def message(s,e,r):return b'stele/v0.1/passport/sign'+b''.join(digest(x) for x in sections(s,e,r,())[:3])


def fixture(rng,count=None):
    def rr():return c.Reference(rng.randint(1,2**64-1),rng.randbytes(32))
    parts=tuple(rr() for _ in range(11));kind=rng.randrange(2)
    s=c.Subject(bytes((kind,))+(parts[5].digest if kind else rng.randbytes(32)),rr(),parts)
    e=c.Evidence(rr() if rng.randrange(2) else None,rr(),rr())
    keys=tuple(sorted((rr() for _ in range(count or rng.randint(1,4))),key=lambda x:x.digest))
    r=c.Registration(rng.randbytes(32),rng.randrange(2**64),rr() if rng.randrange(2) else None,keys)
    signatures=tuple(c.Signature(k.digest,rr()) for k in keys)
    return s,e,r,signatures


def boundaries():
    rng=Random(26950);s,e,r,signatures=fixture(rng,2);e=replace(e,proximity=None);r=replace(r,prior=None)
    raw=c.encode(s,e,r,signatures);assert len(raw)==889+112*2 and len(c.message(s,e,r))==120
    for value in (c.Reference(0,bytes(32)),c.Reference(True,bytes(32)),c.Reference(2**64,bytes(32)),c.Reference(1,bytearray(32))):
        rejects(lambda:c.encode(replace(s,artifact=value),e,r,signatures),'Reference')
    rejects(lambda:c.encode(replace(s,references=s.references[:-1]),e,r,signatures),'References')
    rejects(lambda:c.encode(replace(s,source_identity=b'\2'+bytes(32)),e,r,signatures),'SourceIdentity')
    rejects(lambda:c.encode(s,e,replace(r,timestamp=True),signatures),'Timestamp')
    for keys,reason in (((),'KeyCount'),(r.keys[::-1],'KeyOrder'),((r.keys[0],)*2,'KeyOrder')):
        rejects(lambda:c.encode(s,e,replace(r,keys=keys),signatures),reason)
    for changed in (signatures[:-1],signatures[::-1],(replace(signatures[0],key_id=bytes(32)),)+signatures[1:]):
        rejects(lambda:c.encode(s,e,r,changed),'Signers')
    for changed in (raw[:-1],raw+b'\0',b'x'+raw[1:],raw[:19]+pack('<I',2**32-1)+raw[23:]):rejects(lambda:c.decode(changed),'Encoding')
    rejects(lambda:c.decode(bytearray(raw)),'Capacity');rejects(lambda:c.decode(bytes(c.LIMIT+1)),'Capacity')
    chunks=list(sections(s,e,r,signatures))
    def changed_part(i,at,value):
        altered=list(chunks);part=altered[i];altered[i]=part[:at]+bytes((value,))+part[at+1:]
        return b'stele/v0.1/passport'+b''.join(blob(x) for x in altered)
    rejects(lambda:c.decode(changed_part(0,27,chunks[0][27]^1)),'NumericIdentity')
    rejects(lambda:c.decode(changed_part(1,28,chunks[1][28]^1)),'EvidenceSubject')
    rejects(lambda:c.decode(changed_part(1,60,2)),'Optional')
    rejects(lambda:c.decode(changed_part(2,32,chunks[2][32]^1)),'RegistrationSubject')
    rejects(lambda:c.decode(changed_part(2,64,chunks[2][64]^1)),'RegistrationEvidence')
    rejects(lambda:c.decode(changed_part(3,2,chunks[3][2]^1)),'Signers')
    value=reference(b'original');c.check_reference(value,b'original')
    rejects(lambda:c.check_reference(value,b'changed!'),'ReferenceDigest')
    rejects(lambda:c.check_reference(value,b'old'),'ReferenceLength')
    rejects(lambda:c.check_reference(value,bytearray(b'original')),'Bytes')
    changed=replace(r,timestamp=r.timestamp^1);assert c.message(s,e,changed)!=c.message(s,e,r)
    alternate=c.encode(s,e,changed,signatures);assert c.decode(alternate)==(s,e,changed,signatures)
    rejects(lambda:c.verify(s,e,r,signatures,alternate),'Passport')
    other=(replace(signatures[0],data=reference(b'other signature bytes')),)+signatures[1:]
    assert c.root(s,e,r,other)!=c.root(s,e,r,signatures) and message(s,e,r)==c.message(s,e,r)
    changed_e=replace(e,fidelity=reference(b'other report'));assert c.message(s,changed_e,r)!=c.message(s,e,r)
    changed_s=replace(s,artifact=reference(b'other artifact'));assert c.message(changed_s,e,r)!=c.message(s,e,r)
    return dict(acyclic_identity_controls=True,reference_and_signer_controls=True,signatures_do_not_sign_themselves=True)


def source_joins():
    rng=Random(26951);result=[]
    for kind,groups in ((0,1),(2,3)):
        m,mp,ts,src,assets,files=case(rng,kind,1,groups);scales,artifact=convert(m,mp,ts);sr=scales_codec.encode(m,scales)
        registry=registry_codec.encode(m);bounds=bound_collection.encode(m,sr,registry)
        tail=tuple(reference(x) for x in (b'plan reference fixture',b'private weight reference fixture',b'table reference fixture'))
        s=c.subject_from_files(m,mp,kind,src,assets,files,registry,bounds,tail)
        arch=architecture_frame(kind,m,Fraction(1,100000),m.blocks[0].rotation,0,(m.shape.vocabulary-1,))
        config=b'stele/v0.1/cqis/source-config'+digest(model_frame(m))+digest(map_frame(mp))+digest(assets_frame(assets))+blob(arch)
        raw=(model_frame(m),sr,registry,bounds,preparation(m,mp),source_frame(src),assets_frame(assets),config)
        assert s.references==tuple(reference(x) for x in raw)+tail and s.artifact==reference(artifact)
        assert s.source_identity==(b'\1'+digest(source_frame(src)) if src.kind else b'\0'+src.files[0].sha256)
        assert c.encode_subject(s)==subject_wire(s)
        _,e,r,signatures=fixture(rng);final=digest(wire(s,e,r,signatures))
        request=Request(1,0,(m.shape.vocabulary-1,),None if m.decoding is None else rng.randbytes(32))
        io=public_input.DigestIO(digest(b'stele/v0.1/cqis/token-io'+pack('<IIBI',1,0,0,0)))
        f=public_input.Fields(0,subject_wire(s)[27:59],final,digest(b'instance fixture'),digest(b'ledger fixture'),0,0,io)
        public=public_input.encode_with_numerics(m,sr,registry,bounds,request,f)
        public_input.verify(m,request,f,public);public_input.check_digest_preimage(m,request,f,(0,),(0,))
        substituted=public_input.encode(m,request,replace(f,passport_root=digest(subject_wire(s))))
        rejects(lambda:public_input.verify(m,request,f,substituted),'Statement')
        changed=dict(files);changed['config.json']+=b' '
        rejects(lambda:c.subject_from_files(m,mp,kind,src,assets,changed,registry,bounds,tail),'FileLength')
        rejects(lambda:c.subject_from_files(m,mp,kind,src,assets,files,registry,bounds[:-1]+bytes((bounds[-1]^1,)),tail),'Encoding')
        result.append(dict(layout=kind,source_kind=src.kind,artifact_bytes=len(artifact),public_input_bytes=len(public),subject_id=digest(subject_wire(s)).hex()))
    return result


def full_domain():
    rng=Random(26952);s,e,r,_=fixture(rng,1);keys=tuple(c.Reference(2**64-1,i.to_bytes(32,'big')) for i in range(65535))
    r=replace(r,keys=keys,prior=reference(b'prior'),timestamp=2**64-1);e=replace(e,proximity=reference(b'certificate'))
    signatures=tuple(c.Signature(k.digest,c.Reference(2**64-1,bytes(32))) for k in keys)
    raw=c.encode(s,e,r,signatures);assert raw==wire(s,e,r,signatures) and c.decode(raw)==(s,e,r,signatures)
    assert len(raw)==7340889 and len(c.message(s,e,r))==120
    return dict(keys=len(keys),passport_bytes=len(raw),message_bytes=120,reference_length=2**64-1)


def main():
    rng=Random(2695);corpus=sha256();sources=[0,0];proximity=[0,0]
    for _ in range(10000):
        s,e,r,signatures=fixture(rng);raw=c.encode(s,e,r,signatures)
        assert raw==wire(s,e,r,signatures) and c.decode(raw)==(s,e,r,signatures)
        assert c.message(s,e,r)==message(s,e,r) and c.root(s,e,r,signatures)==digest(raw)
        c.verify(s,e,r,signatures,raw);at=rng.randrange(len(raw));changed=raw[:at]+bytes((raw[at]^1,))+raw[at+1:]
        rejects(lambda:c.verify(s,e,r,signatures,changed),'Passport');corpus.update(raw+c.message(s,e,r))
        sources[s.source_identity[0]]+=1;proximity[int(e.proximity is not None)]+=1
    print(json.dumps(dict(seed=2695,configurations=10000,source_kinds=sources,proximity_presence=proximity,corpus_sha256=corpus.hexdigest(),boundaries=boundaries(),source_joins=source_joins(),full_domain=full_domain()),sort_keys=True))


if __name__=='__main__':main()
