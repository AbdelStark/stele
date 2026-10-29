"""Q26 / RFC-0004 §7, Draft A3/A9: greedy role record, no authenticated logit source."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import greedy_bounds as r


def spec(model):
    m.require(type(model) is m.Model,'Model')
    return r.Spec(len(model.embedding.codes),model.logits_fraction,len(model.blocks[0].attention.rotations))


def records(model):
    s=spec(model)
    return (('decoding.greedy',s,r.encode(s)),)


def check_generation(model,prompt,maximum_new,eos,sequence,stop,rows):
    """Numerical replay helper; plaintext rows must belong to the separately expected model/positions."""
    s=spec(model); c=r.derive(s)
    m.require(type(prompt) is tuple and type(rows) is tuple and len(rows)*s.vocabulary<=c['entry_capacity'],'Rows')
    ws=tuple(r.witness(s,len(prompt)-1+i,row) for i,row in enumerate(rows))
    return r.check_generation(s,c,prompt,maximum_new,eos,sequence,stop,rows,ws)


def evidence(model):
    """Correctness checksum only; a record authenticates neither model nor logit rows."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/greedy-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        r.validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(greedy_bound_records=len(rows),greedy_bound_bytes=sum(len(raw) for _,_,raw in rows),
                greedy_bound_sha256=digest.hexdigest())
