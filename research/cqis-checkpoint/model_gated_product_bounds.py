"""Q26 / Draft RFC-0004 A3/A8: gated-product templates from model metadata only."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import gated_product_bounds as r


def spec(b):
    m.require(type(b) is m.b.Params,'Config')
    return r.Spec(len(b.weights[4].codes),b.fu,b.silu.params[1])


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    for i,b in enumerate(model.blocks):
        s=spec(b); result.append(('layer.'+str(i)+'.gated_product',s,r.encode(s)))
    return tuple(result)


def evidence(model):
    """Correctness checksum only; factor/function ownership is not authenticated here."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/gated-product-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        r.validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(gated_product_records=len(rows),gated_product_bytes=sum(len(raw) for _,_,raw in rows),gated_product_sha256=digest.hexdigest())
