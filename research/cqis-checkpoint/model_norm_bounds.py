"""Q26 / RFC-0021 §2.3, RFC-0022; Draft RFC-0004 A3/A8/A9 model association."""
from pathlib import Path
import hashlib
import sys
import causal_model as model
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import norm_bounds as n
import encoding as e


def spec(p):
    model.require(type(p) is model.b.norm.Parameters,'Parameters')
    return n.Spec(p.d,p.F,p.G,p.E,p.en,p.ed)


def records(value):
    model.require(type(value) is model.Model,'Model'); result=[]
    for i,b in enumerate(value.blocks):
        for role,p in (('norm1',b.norm1),('norm2',b.norm2)):
            s=spec(p); result.append(('layer.'+str(i)+'.'+role,s,e.encode(s)))
    s=spec(value.final_norm); result.append(('final_norm',s,e.encode(s)))
    return tuple(result)


def check(p,raw,xs,gs,w):
    s=spec(p); e.validate(s,raw)
    return n.check_relations(s,n.derive(s),xs,gs,w)


def evidence(value):
    """Correctness checksum only; source/gain ownership is not authenticated here."""
    rows=records(value); digest=hashlib.sha256(b'stele/research/q26/model-norm-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        e.validate(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(norm_bound_records=len(rows),norm_bound_bytes=sum(len(raw) for _,_,raw in rows),norm_bound_sha256=digest.hexdigest())
