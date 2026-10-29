"""Q26 / Draft RFC-0004 A3/A6/A7/A9: rotary roles, no authenticated source consumer."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import rotary_bounds as r


def spec(p,query):
    m.require(type(p) is m.b.pa.Params and type(query) is bool,'Config')
    return r.Spec(p.heads if query else p.groups,p.width,p.rotary,p.layout,p.fq if query else p.fk,len(p.rotations))


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    for i,b in enumerate(model.blocks):
        for role,query in (('query',True),('key',False)):
            s=spec(b.attention,query); result.append(('layer.'+str(i)+'.'+role,s,r.encode(s)))
    return tuple(result)


def check_row(p,query,position,xs,record,w):
    """Expected numerical scope chooses its coefficient row; Q/K source ownership is separate."""
    s=spec(p,query)
    m.require(type(position) is int and 0<=position<s.length,'Position')
    return r.check_relations(s,record,position,xs,p.rotations[position],w)


def evidence(model):
    """Correctness checksum only, not a complete certificate set or canonical coefficient identity."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/rotary-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,s,raw in rows:
        r.validate_bytes(s,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(rotary_bound_records=len(rows),rotary_bound_bytes=sum(len(raw) for _,_,raw in rows),
                rotary_bound_sha256=digest.hexdigest())
