"""Q26 / Draft RFC-0004 A3/A6: per-layer QK score templates, no source authentication."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import attention_score_bounds as r


def spec(p):
    m.require(type(p) is m.b.pa.Params,'Config')
    return r.Spec(p.width,p.fq,p.fk,p.attention.function.params[1],p.q_mode,p.q_scale,p.k_mode,p.k_scale,p.score_m,p.score_e)


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    for i,b in enumerate(model.blocks):
        s=spec(b.attention); result.append(('layer.'+str(i)+'.attention_score',s,r.encode(s)))
    return tuple(result)


def evidence(model):
    """Correctness checksum only; all heads/positions share static policy, not source identity."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/attention-score-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        r.validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(attention_score_records=len(rows),attention_score_bytes=sum(len(raw) for _,_,raw in rows),
                attention_score_sha256=digest.hexdigest())
