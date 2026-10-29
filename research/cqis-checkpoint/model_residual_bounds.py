"""Q26 / Draft RFC-0004 A3/A8/A9: residual role records, no authenticated source consumer."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import residual_bounds as r


def spec(p,attention):
    m.require(type(p) is m.b.Params and type(attention) is bool,'Config')
    return (r.Spec(p.norm1.d,p.norm1.F,p.fo,p.norm2.F) if attention else
            r.Spec(p.norm2.d,p.norm2.F,p.fd,p.fout))


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    for i,b in enumerate(model.blocks):
        for role,attention in (('attention_residual',True),('ffn_residual',False)):
            s=spec(b,attention); result.append(('layer.'+str(i)+'.'+role,s,r.encode(s)))
    return tuple(result)


def evidence(model):
    """Correctness checksum only; expected static metadata does not authenticate residual sources."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/residual-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        r.validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(residual_bound_records=len(rows),residual_bound_bytes=sum(len(raw) for _,_,raw in rows),
                residual_bound_sha256=digest.hexdigest())
