"""Draft RFC-0025 public-input envelope; structural bytes confer no proof authority."""
from dataclasses import dataclass
from struct import pack, unpack_from

from blake3 import blake3

import decoding_execution
from numerics import integer
import preparation_execution
import request_bounds

PREFIX=b'stele/v0.1/public-input'
HEADER=len(PREFIX)+138
LIMIT=1<<23


@dataclass(frozen=True)
class DigestIO:
    digest: bytes


@dataclass(frozen=True)
class CommittedIO:
    input_tree: int
    input_root: bytes
    output_tree: int
    output_root: bytes


@dataclass(frozen=True)
class Fields:
    profile: int
    cqis_id: bytes
    passport_root: bytes
    plan_id: bytes
    ledger_id: bytes
    generated: int
    reason: int
    io: DigestIO | CommittedIO


def _digest(value):
    if type(value) is not bytes or len(value)!=32:raise ValueError('Digest')


def _fields(boundary,f):
    if type(f) is not Fields:raise ValueError('Parameters')
    integer(f.profile,0,1,'Profile')
    for value in (f.cqis_id,f.passport_root,f.plan_id,f.ledger_id):_digest(value)
    integer(f.generated,0,boundary.maximum_new,'Length');integer(f.reason,0,1,'Stop')
    if (f.reason==0 and f.generated!=boundary.maximum_new) or (f.reason==1 and f.generated==0):raise ValueError('Stop')
    if type(f.io) is DigestIO:
        _digest(f.io.digest);io=b'\0'+f.io.digest
    elif type(f.io) is CommittedIO:
        integer(f.io.input_tree,0,2**64-1,'TreeId');integer(f.io.output_tree,0,2**64-1,'TreeId')
        if f.io.input_tree==f.io.output_tree:raise ValueError('TreeId')
        _digest(f.io.input_root);_digest(f.io.output_root)
        io=b'\1'+pack('<Q',f.io.input_tree)+f.io.input_root+pack('<Q',f.io.output_tree)+f.io.output_root
    else:raise ValueError('IOMode')
    n=boundary.prompt_length+f.generated
    return io,n,1<<((n-1).bit_length())


def geometry(model,boundary,f):
    decoding_execution.policy(model,boundary)
    return _fields(boundary,f)[1:]


def encode(model,boundary,f):
    policy=decoding_execution.policy(model,boundary);io,_,_=_fields(boundary,f)
    raw=(PREFIX+bytes((f.profile,))+f.cqis_id+f.passport_root+f.plan_id+f.ledger_id
         +pack('<IBI',f.generated,f.reason,len(policy))+policy+io)
    if len(raw)>LIMIT:raise ValueError('Capacity')
    return raw


def decode(model,boundary,raw):
    if type(raw) is not bytes or len(raw)>LIMIT:raise ValueError('Capacity')
    policy=decoding_execution.policy(model,boundary);at=HEADER+len(policy)
    if len(raw)<=at or not raw.startswith(PREFIX):raise ValueError('Encoding')
    if unpack_from('<I',raw,HEADER-4)[0]!=len(policy) or raw[HEADER:at]!=policy:raise ValueError('Policy')
    mode=raw[at];payload=at+1
    if mode==0 and len(raw)==payload+32:io=DigestIO(raw[payload:])
    elif mode==1 and len(raw)==payload+80:
        io=CommittedIO(unpack_from('<Q',raw,payload)[0],raw[payload+8:payload+40],
                       unpack_from('<Q',raw,payload+40)[0],raw[payload+48:payload+80])
    else:raise ValueError('Encoding')
    identities=tuple(raw[len(PREFIX)+1+32*i:len(PREFIX)+1+32*(i+1)] for i in range(4))
    g,reason=unpack_from('<IB',raw,len(PREFIX)+129)
    f=Fields(raw[len(PREFIX)],*identities,g,reason,io);_fields(boundary,f)
    return f


def verify(model,boundary,expected,raw):
    if type(raw) is not bytes or len(raw)>LIMIT:raise ValueError('Capacity')
    if raw!=encode(model,boundary,expected):raise ValueError('Statement')


def encode_with_numerics(model,scales,registry,bounds,boundary,f):
    raw=encode(model,boundary,f)
    # This derives numerical identity only; it cannot authenticate the other roots.
    if f.cqis_id!=preparation_execution.identity(model,scales,registry,bounds):raise ValueError('CQIS')
    return raw


def check_digest_preimage(model,boundary,f,prompt,sequence):
    """Plaintext boundary/hash evidence only; no forward evaluation or proof check."""
    encode(model,boundary,f)
    if type(f.io) is not DigestIO:raise ValueError('IOMode')
    spec=request_bounds.Spec(model.shape.vocabulary,model.shape.context,int(model.decoding is not None))
    raw=request_bounds.encode_io(spec,boundary,prompt,sequence,f.reason)
    if len(sequence)-len(prompt)!=f.generated:raise ValueError('IOLength')
    if blake3(raw).digest()!=f.io.digest:raise ValueError('IOIdentity')
