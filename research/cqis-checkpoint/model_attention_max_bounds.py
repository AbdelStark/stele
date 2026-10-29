"""Q26 / RFC-0009 A1, Draft RFC-0004 A3/A6: maximum templates derived from score policy."""
import hashlib
import model_attention_score_bounds as score
from attention_max_bounds import Spec, encode, validate_bytes
m=score.m


def spec(p):
    m.require(type(p) is m.b.pa.Params,'Config')
    maximum=score.r.derive(score.spec(p))['score_max']; b,f=p.attention.function.params[:2]
    return Spec(len(p.rotations),maximum,b,f)


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    for i,b in enumerate(model.blocks):
        s=spec(b.attention); result.append(('layer.'+str(i)+'.attention_max',s,encode(s)))
    return tuple(result)


def evidence(model):
    """Correctness checksum only; expected static score bound comes from the same model policy."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/attention-max-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(attention_max_records=len(rows),attention_max_bytes=sum(len(raw) for _,_,raw in rows),attention_max_sha256=digest.hexdigest())
