"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: shared-head accumulation templates."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import attention_sum_bounds as r


def spec(p):
    m.require(type(p) is m.b.pa.Params,'Config'); a=p.attention
    return r.Spec(len(p.rotations),p.width,a.fv,a.function.params[2],a.value_mode,a.value_scale,a.accumulation)


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    for i,b in enumerate(model.blocks):
        s=spec(b.attention); result.append(('layer.'+str(i)+'.attention_sum',s,r.encode(s)))
    return tuple(result)


def evidence(model):
    """Correctness checksum only; actual head/GQA views, scales and probabilities need consumers."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/attention-sum-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        r.validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(attention_sum_records=len(rows),attention_sum_bytes=sum(len(raw) for _,_,raw in rows),
                attention_sum_sha256=digest.hexdigest())
