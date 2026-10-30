"""Q26 / Draft RFC-0004 A3/A6, RFC-0009 A2: shared-head normalization templates."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import attention_normalization_bounds as r


def spec(p):
    m.require(type(p) is m.b.pa.Params,'Config'); a=p.attention
    return r.Spec(len(p.rotations),p.width,a.fv,a.fo,a.function.params[2],a.value_mode,a.value_scale,a.accumulation,a.drop)


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    for i,b in enumerate(model.blocks):
        s=spec(b.attention); result.append(('layer.'+str(i)+'.attention_normalization',s,r.encode(s)))
    return tuple(result)


def evidence(model):
    """Correctness checksum only; source/divisor/rounding and output conversion need consumers."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/attention-normalization-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        r.validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(attention_normalization_records=len(rows),attention_normalization_bytes=sum(len(raw) for _,_,raw in rows),
                attention_normalization_sha256=digest.hexdigest())
