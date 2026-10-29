"""Q26: static scaled-linear roles of the A9 numerical model, no complete certificate set."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import scaled_linear as s


def records(model):
    """Expected metadata must be authenticated separately; never scan codes for observed bounds."""
    m.require(type(model) is m.Model,'Model'); result=[]
    def add(role,w,fx,fo,policy,kind='wide'):
        spec=s.Spec(kind,1 if kind=='embedding' else len(w.codes[0]),w.bits,w.exponent,fx,fo,*policy)
        result.append((role,spec,s.encode(spec)))
    add('embedding',model.embedding,0,model.blocks[0].norm1.F,('static',1),'embedding')
    for i,b in enumerate(model.blocks):
        p=b.attention; a=p.attention; prefix='layer.'+str(i)+'.'
        for role,w,fo in zip(('q','k','v'),b.weights[:3],(p.fq,p.fk,a.fv)):
            add(prefix+role,w,b.norm1.E,fo,b.first)
        add(prefix+'o',b.weights[3],a.fo,b.fo,(a.output_mode,a.output_scale))
        add(prefix+'up',b.weights[4],b.norm2.E,b.fu,b.second)
        add(prefix+'gate',b.weights[5],b.norm2.E,b.silu.params[0],b.second)
        add(prefix+'down',b.weights[6],b.fu+b.silu.params[1],b.fd,b.gated,'gated')
    add('head',model.embedding if model.head is None else model.head,model.final_norm.E,model.logits_fraction,model.policy)
    return tuple(result)


def evidence(model):
    """Fixture checksum only: neither a complete certificate set nor cqis_id."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/scaled-linear-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,spec,raw in rows:
        s.validate_bytes(spec,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(scaled_linear_records=len(rows),scaled_linear_bytes=sum(len(raw) for _,_,raw in rows),
                scaled_linear_sha256=digest.hexdigest())
