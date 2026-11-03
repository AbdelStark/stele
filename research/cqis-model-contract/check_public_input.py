"""Draft RFC-0025 public envelope evidence; no passport or inference verifier."""
from dataclasses import replace
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3

from check_arithmetic_bounds import rejects
from check_decoding_execution import fixture, policy_oracle
from check_model_codec import oracle as model_wire
from check_model_execution import fixture as numerical_fixture
from check_request_bounds import io_wire
import bound_collection
import registry_codec
from request_bounds import Request
import public_input as c


def frame(m,r,f):
    p=policy_oracle(m,r)
    io=b'\0'+f.io.digest if type(f.io) is c.DigestIO else b'\1'+pack('<Q',f.io.input_tree)+f.io.input_root+pack('<Q',f.io.output_tree)+f.io.output_root
    return (b'stele/v0.1/public-input'+pack('<B',f.profile)+f.cqis_id+f.passport_root+f.plan_id+f.ledger_id
            +pack('<IBI',f.generated,f.reason,len(p))+p+io)


def fields(rng,g,reason,io,profile=0):
    return c.Fields(profile,*(rng.randbytes(32) for _ in range(4)),g,reason,io)


def templates(rng):
    return [fixture(rng,family,mode,7,64)[0] for family in range(2) for mode in (-1,0,1,2)]


def boundaries(models):
    rng=Random(26940);m=models[1];r=Request(2,4,(6,),rng.randbytes(32));prompt=(6,2);sequence=prompt+(0,6)
    f=fields(rng,2,1,c.DigestIO(blake3(io_wire(r,prompt,sequence,1)).digest()))
    raw=c.encode(m,r,f);assert c.decode(m,r,raw)==f and c.geometry(m,r,f)==(4,4)
    c.check_digest_preimage(m,r,f,prompt,sequence)
    for changed in (replace(f,profile=True),replace(f,profile=2)):rejects(lambda:c.encode(m,r,changed),'Profile')
    for changed in (replace(f,generated=True),replace(f,generated=5)):rejects(lambda:c.encode(m,r,changed),'Length')
    for changed in (replace(f,reason=True),replace(f,reason=2),replace(f,generated=0),replace(f,reason=0)):
        rejects(lambda:c.encode(m,r,changed),'Stop')
    rejects(lambda:c.encode(m,r,replace(f,cqis_id=bytes(31))),'Digest')
    rejects(lambda:c.encode(m,r,replace(f,io=c.DigestIO(bytearray(32)))),'Digest')
    rejects(lambda:c.encode(m,r,replace(f,io=None)),'IOMode')
    for changed in (raw[:-1],raw+b'\0',b'x'+raw[1:]):rejects(lambda:c.decode(m,r,changed),'Encoding')
    rejects(lambda:c.decode(m,r,bytearray(raw)),'Capacity')
    rejects(lambda:c.decode(m,r,bytes(c.LIMIT+1)),'Capacity')
    changed=raw[:157]+pack('<I',2**32-1)+raw[161:];rejects(lambda:c.decode(m,r,changed),'Policy')
    changed=raw[:23]+b'\2'+raw[24:];rejects(lambda:c.decode(m,r,changed),'Profile')
    changed=raw[:156]+b'\2'+raw[157:];rejects(lambda:c.decode(m,r,changed),'Stop')
    changed=raw[:152]+pack('<I',2+2147483647)+raw[156:];rejects(lambda:c.decode(m,r,changed),'Length')
    changed=raw[:-33]+b'\2'+raw[-32:];rejects(lambda:c.decode(m,r,changed),'Encoding')
    rejects(lambda:c.decode(m,replace(r,eos=(5,)),raw),'Policy')
    changed_model=replace(m,decoding=replace(m.decoding,tn=m.decoding.tn+m.decoding.td))
    rejects(lambda:c.decode(changed_model,r,raw),'Policy')
    for key in ('cqis_id','passport_root','plan_id','ledger_id'):
        other=replace(f,**{key:bytes(32)});encoded=c.encode(m,r,other);assert c.decode(m,r,encoded)==other
        rejects(lambda:c.verify(m,r,f,encoded),'Statement')
    for other in (replace(f,profile=1),replace(f,generated=3),replace(f,io=c.DigestIO(bytes(32)))):
        encoded=c.encode(m,r,other);assert c.decode(m,r,encoded)==other;rejects(lambda:c.verify(m,r,f,encoded),'Statement')
    rejects(lambda:c.check_digest_preimage(m,r,f,(5,2),sequence),'Prefix')
    rejects(lambda:c.check_digest_preimage(m,r,f,prompt,prompt+(1,6)),'IOIdentity')
    rejects(lambda:c.check_digest_preimage(m,r,f,prompt,prompt+(6,6)),'Stop')
    rejects(lambda:c.check_digest_preimage(m,r,f,prompt,prompt+(0,0)),'Stop')
    rejects(lambda:c.check_digest_preimage(m,r,replace(f,generated=3),prompt,sequence),'IOLength')
    committed=replace(f,io=c.CommittedIO(0,bytes(32),2**64-1,bytes(32)))
    assert c.decode(m,r,c.encode(m,r,committed))==committed
    other=c.encode(m,r,committed);changed=other[:-40]+bytes(8)+other[-32:]
    rejects(lambda:c.decode(m,r,changed),'TreeId')
    rejects(lambda:c.check_digest_preimage(m,r,committed,prompt,sequence),'IOMode')
    for io in (replace(committed.io,input_tree=True),replace(committed.io,output_tree=2**64),replace(committed.io,output_tree=0)):
        rejects(lambda:c.encode(m,r,replace(committed,io=io)),'TreeId')
    for key,value in (('input_tree',1),('output_tree',2),('input_root',bytes([1])*32),('output_root',bytes([2])*32)):
        other=replace(committed,io=replace(committed.io,**{key:value}));encoded=c.encode(m,r,other)
        assert c.decode(m,r,encoded)==other;rejects(lambda:c.verify(m,r,committed,encoded),'Statement')
    zero=Request(64,0,(6,),r.seed_commitment);zf=replace(committed,generated=0,reason=0)
    assert c.geometry(m,zero,zf)==(64,64) and c.decode(m,zero,c.encode(m,zero,zf))==zf
    rejects(lambda:c.encode(m,zero,replace(zf,reason=1)),'Stop')
    return dict(structural_and_expected_controls=True,digest_source_controls=True,empty_output_reference_retained=True,tree_id_maximum=2**64-1)


def numerical_joins():
    rng=Random(26941);result=[]
    for family in range(2):
        m,_,scales,_,_=numerical_fixture(rng,family,layers=1)
        registry=registry_codec.encode(m);bounds=bound_collection.encode(m,scales,registry)
        preimage=b'stele/v0.1/cqis/identity'+b''.join(blake3(x).digest() for x in (model_wire(m),scales,registry,bounds))
        r=Request(1,0,(m.shape.vocabulary-1,),None if m.decoding is None else rng.randbytes(32))
        io=c.DigestIO(blake3(io_wire(r,(0,),(0,),0)).digest());f=replace(fields(rng,0,0,io),cqis_id=blake3(preimage).digest())
        raw=c.encode_with_numerics(m,scales,registry,bounds,r,f);assert raw==frame(m,r,f)
        c.verify(m,r,f,raw);c.check_digest_preimage(m,r,f,(0,),(0,))
        rejects(lambda:c.encode_with_numerics(m,scales,registry,bounds,r,replace(f,cqis_id=bytes(32))),'CQIS')
        rejects(lambda:c.encode_with_numerics(m,scales,registry,bounds[:-1]+bytes((bounds[-1]^1,)),r,f),'Encoding')
        rejects(lambda:c.encode_with_numerics(m,scales,b'X'+registry[1:],bounds,r,f),'Structure')
        result.append(dict(family=family,statement_bytes=len(raw),cqis_id=f.cqis_id.hex()))
    return result


def full_domain(m):
    n=1<<20;s=replace(m.shape,vocabulary=n,context=n)
    blocks=tuple(replace(b,exp=replace(b.exp,n=n),rotation=replace(b.rotation,length=n) if b.rotation else None) for b in m.blocks)
    m=replace(m,shape=s,blocks=blocks,decoding=replace(m.decoding,exp=replace(m.decoding.exp,n=n)))
    r=Request(n,0,tuple(range(n)),bytes(32));tokens=(0,)*n
    io=c.DigestIO(blake3(io_wire(r,tokens,tokens,0)).digest());f=c.Fields(1,*(bytes(32) for _ in range(4)),0,0,io)
    raw=c.encode(m,r,f);assert raw==frame(m,r,f) and c.decode(m,r,raw)==f and c.geometry(m,r,f)==(n,n)
    c.check_digest_preimage(m,r,f,tokens,tokens)
    committed=replace(f,io=c.CommittedIO(1,bytes(32),2,bytes(32)));other=c.encode(m,r,committed)
    assert other==frame(m,r,committed) and c.decode(m,r,other)==committed
    return dict(eos_count=n,actual_tokens=n,digest_bytes=len(raw),commitment_bytes=len(other))


def main():
    rng=Random(2694);models=templates(rng);corpus=sha256();modes=[0,0];profiles=[0,0]
    for i in range(10000):
        m=models[i%len(models)];v,n=m.shape.vocabulary,m.shape.context
        q=rng.randint(1,n);a=rng.randint(0,n-q);eos=tuple(sorted(rng.sample(range(v),rng.randint(1,v-1))))
        r=Request(q,a,eos,None if m.decoding is None else rng.randbytes(32));reason=rng.randrange(2) if a else 0
        g=rng.randint(1,a) if reason else a;allowed=tuple(t for t in range(v) if t not in eos)
        prompt=tuple(rng.randrange(v) for _ in range(q));generated=tuple(rng.choice(allowed) for _ in range(max(0,g-1)))
        if g:generated+=(rng.choice(eos if reason else allowed),)
        sequence=prompt+generated
        io=c.CommittedIO(rng.randrange(2**63),rng.randbytes(32),rng.randrange(2**63,2**64),rng.randbytes(32)) if i%2 else c.DigestIO(blake3(io_wire(r,prompt,sequence,reason)).digest())
        f=fields(rng,g,reason,io,(i//2)%2);raw=c.encode(m,r,f)
        assert raw==frame(m,r,f) and c.decode(m,r,raw)==f and c.geometry(m,r,f)==(q+g,2**((q+g-1).bit_length()))
        c.verify(m,r,f,raw)
        if type(io) is c.DigestIO:c.check_digest_preimage(m,r,f,prompt,sequence)
        at=rng.randrange(len(raw));changed=raw[:at]+bytes((raw[at]^1,))+raw[at+1:];rejects(lambda:c.verify(m,r,f,changed),'Statement')
        corpus.update(raw);modes[i%2]+=1;profiles[f.profile]+=1
    print(json.dumps(dict(seed=2694,configurations=10000,io_modes=modes,profiles=profiles,corpus_sha256=corpus.hexdigest(),boundaries=boundaries(models),numerical_joins=numerical_joins(),full_domain=full_domain(models[-1])),sort_keys=True))


if __name__=='__main__':main()
