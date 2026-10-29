"""Q26 / Draft RFC-0004 A10: canonical causal configuration, not a passport."""
from dataclasses import dataclass
from blake3 import blake3
import artifact
import causal_model as m
import rope
from quantiser import require

r=m.b.records
a=m.b.pa.a
fn=a.fn
TAG=b'stele/research/q26/model/v1\0'
INSTANCE=b'stele/research/q26/model-instance/v1\0'


def policy(p):
    require(type(p) is tuple and len(p)==2,'Policy'); a.policy(*p)


def record(s,shape,bits,parameter):
    r.config(s)
    require(s.shape==shape and s.bits in bits and s.parameter==parameter,'Record')


@dataclass(frozen=True)
class Projection:
    heads: int
    groups: int
    width: int
    fq: int
    fk: int
    q_mode: str
    q_scale: int
    k_mode: str
    k_scale: int
    score_m: int
    score_e: int
    attention: a.Config
    representation: fn.Representation
    rotation: rope.Parameters | None

    def __post_init__(self):
        a.integer(self.heads,1,128,'Heads'); a.integer(self.groups,1,self.heads,'Heads')
        require(self.heads%self.groups==0,'Heads'); a.integer(self.width,1,16384//self.heads,'Shape')
        for f in (self.fq,self.fk): a.integer(f,0,30,'Units')
        a.policy(self.q_mode,self.q_scale); a.policy(self.k_mode,self.k_scale)
        a.integer(self.score_m,1,65535,'ScoreScale'); a.integer(self.score_e,-62,30,'ScoreScale')
        require(type(self.attention) is a.Config,'Config')
        require(type(self.representation) is fn.Representation and self.representation.function==self.attention.function,'Representation')
        require(self.rotation is None or (type(self.rotation) is rope.Parameters and self.rotation.width<=self.width),'Rotation')
        # The source-unit bounds are the same static calculation used by A6 evaluation.
        require(m.b.pa.bounds(self)['score_abs_max']<1 << 31,'ScoreBound')


@dataclass(frozen=True)
class Block:
    norm1: m.b.norm.Parameters
    norm2: m.b.norm.Parameters
    gain1: r.Spec
    gain2: r.Spec
    weights: tuple
    projection: Projection
    silu: fn.Function
    fu: int
    fo: int
    fd: int
    fout: int
    first: tuple
    second: tuple
    gated: tuple

    def __post_init__(self):
        require(type(self.norm1) is m.b.norm.Parameters and type(self.norm2) is m.b.norm.Parameters,'Norm')
        d=self.norm1.d; require(self.norm2.d==d,'Shape')
        for s,n in ((self.gain1,self.norm1),(self.gain2,self.norm2)): record(s,(d,),(16,),n.G)
        require(type(self.projection) is Projection,'Config'); p=self.projection
        require(type(self.weights) is tuple and len(self.weights)==7 and all(type(w) is r.Spec for w in self.weights),'Weights')
        for w in self.weights: r.config(w); require(len(w.shape)==2,'Record')
        hidden=self.weights[4].shape[0]; a.integer(hidden,1,16384,'Shape')
        shapes=((p.heads*p.width,d),(p.groups*p.width,d),(p.groups*p.width,d),(d,p.heads*p.width),
                (hidden,d),(hidden,d),(d,hidden))
        for w,shape in zip(self.weights,shapes): record(w,shape,(4,8),0)
        require(type(self.silu) is fn.Function and self.silu.name=='silu_q','Function')
        require(self.silu.params[1]<=self.silu.params[0],'Overflow')
        for f in (self.fu,self.fo,self.fd,self.fout): a.integer(f,0,30,'Units')
        for p in (self.first,self.second,self.gated): policy(p)


@dataclass(frozen=True)
class Config:
    length: int
    embedding: r.Spec
    head: r.Spec | None
    blocks: tuple
    final_norm: m.b.norm.Parameters
    gain: r.Spec
    policy: tuple
    logits_fraction: int

    def __post_init__(self):
        a.integer(self.length,1,1 << 20,'Length'); r.config(self.embedding)
        require(len(self.embedding.shape)==2,'Record'); vocab,d=self.embedding.shape
        a.integer(vocab,1,1 << 20,'Shape'); a.integer(d,1,16384,'Shape')
        record(self.embedding,(vocab,d),(4,8),0)
        if self.head is not None: record(self.head,(vocab,d),(4,8),0)
        require(type(self.blocks) is tuple and 1<=len(self.blocks)<=128 and all(type(b) is Block for b in self.blocks),'Blocks')
        require(all(b.norm1.d==d for b in self.blocks),'Shape')
        require(type(self.final_norm) is m.b.norm.Parameters and self.final_norm.d==d,'Shape')
        require(all(l.fout==v.norm1.F for l,v in zip(self.blocks,self.blocks[1:])) and self.blocks[-1].fout==self.final_norm.F,'Units')
        require(all(b.projection.rotation is None or b.projection.rotation.length==self.length for b in self.blocks),'Length')
        record(self.gain,(d,),(16,),self.final_norm.G); policy(self.policy); a.integer(self.logits_fraction,0,30,'Units')
        # The only supported alias is head=None: no second embedding record exists.
        artifact.ordered(specs(self)); representations(self)


def specs(p):
    return [p.embedding]+([] if p.head is None else [p.head])+[p.gain]+[s for b in p.blocks for s in (b.gain1,b.gain2)+b.weights]


def uint(x,n): return x.to_bytes(n,'little')
def blob(raw): return uint(len(raw),2)+raw
def norm_bytes(p): return uint(p.d,2)+bytes([p.F,p.G,p.E])+uint(p.en,4)+uint(p.ed,4)
def policy_bytes(p): return bytes([('dynamic','static').index(p[0])])+uint(p[1],2)


def representations(p):
    """Unique configured RFC-0021 function/representation choices; no table admission."""
    values=[fn.Representation(fn.Function('rmsnorm_q',1,norm_bytes(p.final_norm)),3,b'')]
    for b in p.blocks:
        values.extend(fn.Representation(fn.Function('rmsnorm_q',1,norm_bytes(n)),3,b'') for n in (b.norm1,b.norm2))
        values.extend((b.projection.representation,fn.Representation(b.silu,0,b'')))
    chosen={}
    for v in values:
        key=fn.function_id(v.function)
        require(key not in chosen or chosen[key]==v,'Representation')
        chosen[key]=v
    return tuple(chosen[k] for k in sorted(chosen))


def encode(p):
    require(type(p) is Config,'Config')
    spec=lambda s:blob(r.config(s))
    raw=TAG+uint(p.length,4)+uint(len(p.blocks),2)+spec(p.embedding)+bytes([p.head is not None])
    if p.head is not None: raw+=spec(p.head)
    raw+=norm_bytes(p.final_norm)+spec(p.gain)+policy_bytes(p.policy)+bytes([p.logits_fraction])
    for b in p.blocks:
        raw+=norm_bytes(b.norm1)+norm_bytes(b.norm2)+spec(b.gain1)+spec(b.gain2)+b''.join(spec(s) for s in b.weights)
        q=b.projection; v=q.attention
        raw+=uint(q.heads,2)+uint(q.groups,2)+uint(q.width,2)+bytes([q.fq,q.fk])
        raw+=policy_bytes((q.q_mode,q.q_scale))+policy_bytes((q.k_mode,q.k_scale))
        raw+=uint(q.score_m,2)+q.score_e.to_bytes(1,'little',signed=True)+blob(b'' if q.rotation is None else rope.encode(q.rotation))
        raw+=bytes([v.fv,v.fo])+policy_bytes((v.value_mode,v.value_scale))+policy_bytes((v.output_mode,v.output_scale))
        raw+=bytes([('exact','block1024').index(v.accumulation),v.drop])
        raw+=blob(fn.encode(v.function))+blob(fn.encode_representation(q.representation))+blob(fn.encode(b.silu))
        raw+=bytes([b.fu,b.fo,b.fd,b.fout])+policy_bytes(b.first)+policy_bytes(b.second)+policy_bytes(b.gated)
    require(len(raw)<=1 << 20,'Capacity'); return raw


class Reader:
    def __init__(self,raw):
        require(type(raw) is bytes,'Bytes'); require(len(raw)<=1 << 20,'Capacity'); self.raw=raw; self.pos=0

    def take(self,n):
        require(n<=len(self.raw)-self.pos,'Truncated'); out=self.raw[self.pos:self.pos+n]; self.pos+=n; return out

    def u(self,n,signed=False): return int.from_bytes(self.take(n),'little',signed=signed)
    def blob(self,limit):
        n=self.u(2); require(n<=limit,'Capacity'); return self.take(n)

    def end(self): require(self.pos==len(self.raw),'Trailing')
    def norm(self): return m.b.norm.Parameters(self.u(2),self.u(1),self.u(1),self.u(1),self.u(4),self.u(4))
    def policy(self):
        kind=self.u(1); require(kind<2,'Mode'); return ('dynamic','static')[kind],self.u(2)

    def spec(self):
        raw=self.blob(512); t=Reader(raw); require(t.take(len(r.CONFIG))==r.CONFIG,'Record')
        name=t.blob(255); require(name.isascii(),'Name')
        source,rank=t.u(1),t.u(1); require(1<=source<=4 and rank in (1,2),'Record')
        s=r.Spec(name.decode('ascii'),r.SOURCES[source-1],tuple(t.u(4) for _ in range(rank)),t.u(1),t.u(1))
        t.end(); require(r.config(s)==raw,'Record'); return s


def decode(raw):
    t=Reader(raw); require(t.take(len(TAG))==TAG,'Prefix'); length,count=t.u(4),t.u(2)
    a.integer(length,1,1 << 20,'Length'); a.integer(count,1,128,'Blocks')
    embedding=t.spec(); untied=t.u(1); require(untied<2,'Tied'); head=t.spec() if untied else None
    final,gain,policy_value,logits=t.norm(),t.spec(),t.policy(),t.u(1); blocks=[]
    for _ in range(count):
        n1,n2,g1,g2=t.norm(),t.norm(),t.spec(),t.spec(); weights=tuple(t.spec() for _ in range(7))
        h,g,w,fq,fk=t.u(2),t.u(2),t.u(2),t.u(1),t.u(1); qp,kp=t.policy(),t.policy()
        sm,se=t.u(2),t.u(1,True); rotation=t.blob(128); rotation=rope.decode(rotation) if rotation else None
        fv,fo=t.u(1),t.u(1); vp,op=t.policy(),t.policy(); mode,drop=t.u(1),t.u(1); require(mode<2,'Mode')
        f=fn.decode(t.blob(128)); rep=fn.decode_representation(f,t.blob(256)); silu=fn.decode(t.blob(128))
        att=a.Config(f,fv,fo,*vp,*op,('exact','block1024')[mode],drop)
        projection=Projection(h,g,w,fq,fk,*qp,*kp,sm,se,att,rep,rotation)
        blocks.append(Block(n1,n2,g1,g2,weights,projection,silu,t.u(1),t.u(1),t.u(1),t.u(1),t.policy(),t.policy(),t.policy()))
    t.end(); result=Config(length,embedding,head,tuple(blocks),final,gain,policy_value,logits)
    require(encode(result)==raw,'Canonical'); return result


def identity(p): return blake3(encode(p)).digest()


def hash32(value): require(type(value) is bytes and len(value)==32,'Digest')


def instance_identity(config_id,artifact_digest):
    hash32(config_id); hash32(artifact_digest); return blake3(INSTANCE+config_id+artifact_digest).digest()


def load(expected_config,raw,expected_artifact,data):
    """Reconstruct only from separately expected hashes; those hashes need external authentication."""
    hash32(expected_config); hash32(expected_artifact); p=decode(raw)
    require(identity(p)==expected_config,'Identity'); selected=specs(p)
    # Reject large materializations before parsing physical payloads or generating rotations.
    require(all(r.count(s)<=1 << 20 for s in selected) and sum(r.count(s) for s in selected)<=1 << 22,'Capacity')
    require(all(sum(r.count(s) for s in b.weights)<=1 << 20 for b in p.blocks),'Capacity')
    rotations=tuple(dict.fromkeys(b.projection.rotation for b in p.blocks))
    require(all(q is None or q.length*(q.width//2)<=1 << 16 for q in rotations),'Capacity')
    require(sum(p.length if q is None else q.length*(q.width//2) for q in rotations)<=1 << 20,'Capacity')
    expected_size=len(artifact.DATA)+36+sum(8+artifact.record_size(s) for s in selected)
    require(type(data) is bytes and len(data)==expected_size,'ArtifactLength')
    require(blake3(data).digest()==expected_artifact,'ArtifactDigest'); physical=artifact.parse(selected,data)
    def matrix(s):
        out=r.parse(s,physical[s.name]); n,k=s.shape
        return m.b.Matrix(s.bits,out['exponent'],tuple(out['mantissas']),tuple(tuple(out['values'][i*k:(i+1)*k]) for i in range(n)))
    def gains(s): return tuple(r.parse(s,physical[s.name])['values'])
    generated={}
    for q in rotations:
        generated[q]=tuple(() for _ in range(p.length)) if q is None else tuple(
            tuple((v['cos'],v['sin']) for v in (rope.certify(q,t,j) for j in range(q.width//2))) for t in range(q.length))
    blocks=[]
    for b in p.blocks:
        q=b.projection; rp=q.rotation
        attention=m.b.pa.Params(q.heads,q.groups,q.width,0 if rp is None else rp.width,'adjacent' if rp is None else rp.layout,
            q.fq,q.fk,q.q_mode,q.q_scale,q.k_mode,q.k_scale,q.score_m,q.score_e,q.attention,generated[rp])
        blocks.append(m.b.Params(b.norm1,b.norm2,gains(b.gain1),gains(b.gain2),tuple(matrix(s) for s in b.weights),
            attention,b.silu,b.fu,b.fo,b.fd,b.fout,b.first,b.second,b.gated))
    return m.Model(matrix(p.embedding),None if p.head is None else matrix(p.head),tuple(blocks),p.final_norm,
                   gains(p.gain),p.policy,p.logits_fraction)
