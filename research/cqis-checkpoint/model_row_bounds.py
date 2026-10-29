"""Q26 / Draft RFC-0004 A3/A8/A9: model row roles, not a full certificate set."""
from pathlib import Path
import hashlib
import sys
import causal_model as m
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'cqis-bounds'))
import row_bounds as r


def records(model):
    m.require(type(model) is m.Model,'Model'); result=[]
    def add(role,dimension,fraction,policy,kind='wide'):
        spec=r.Spec(kind,dimension,fraction,*policy); result.append((role,spec,r.encode(spec)))
    for i,b in enumerate(model.blocks):
        p=b.attention; a=p.attention; prefix='layer.'+str(i)+'.'
        add(prefix+'first',b.norm1.d,b.norm1.E,b.first)
        add(prefix+'query',p.heads*p.width,p.fq,(p.q_mode,p.q_scale))
        add(prefix+'key',p.groups*p.width,p.fk,(p.k_mode,p.k_scale))
        add(prefix+'value',p.groups*p.width,a.fv,(a.value_mode,a.value_scale))
        add(prefix+'attention',p.heads*p.width,a.fo,(a.output_mode,a.output_scale))
        add(prefix+'second',b.norm2.d,b.norm2.E,b.second)
        add(prefix+'gated',len(b.weights[4].codes),b.fu+b.silu.params[1],b.gated,'gated')
    add('final',model.final_norm.d,model.final_norm.E,model.policy)
    return tuple(result)


def evidence(model):
    """Test fixture checksum only; never a passport, cqis_id or source authentication."""
    rows=records(model); digest=hashlib.sha256(b'stele/research/q26/row-bounds-checksum/v1\0')
    digest.update(len(rows).to_bytes(4,'little'))
    for name,spec,raw in rows:
        r.validate_bytes(spec,raw); name=name.encode('ascii')
        digest.update(len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw)
    return dict(row_bound_records=len(rows),row_bound_bytes=sum(len(raw) for _,_,raw in rows),
                row_bound_sha256=digest.hexdigest())
