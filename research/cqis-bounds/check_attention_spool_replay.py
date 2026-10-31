# /// script
# requires-python = "==3.12.*"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: every stored byte must survive replay authentication."""
from dataclasses import replace
import hashlib
import json
import struct
import sys
import tempfile
import check_attention_block_offset as weighted
import check_attention_block_values as restored


def controls():
    count=0
    for d in (4,8):
        for scale in (1,2):
            c=weighted.c;r=c.r;p=weighted.spec(1,1);p=replace(p,schema=replace(p.schema,scale=scale));v=c.derive(p,d);value=v['constants']['restored_max'];partial=c.columns(v);c.accumulate(v,partial,[1],[value]);output,carry=c.finish_columns(v,partial);roots=[]
            for i,xs in enumerate(([1],[value],output,carry)):
                plan=c.range_spec(p,v,i);_,_,n,width,*_=r.derive(plan,d);roots.append(r.source_root(plan,c.planes(xs,n,width)))
            width=r.derive(c.range_spec(p,v,1),d)[3];assert width in (1,2);local=dict(probability=[1],output=output,carry=carry);expected=weighted.oracle(p,[1],[value])[1];states=[bytes(32)]*v['children']
            with tempfile.TemporaryFile() as spool:
                spool.write(struct.pack('<I',value));c.parent(p,v,expected,roots,states,local,spool,d)
                for byte in range(width,4):
                    spool.seek(byte);spool.write(b'\x01');weighted.rejects('Value:0:CommitmentMismatch',lambda:c.parent(p,v,expected,roots,states,local,spool,d));spool.seek(byte);spool.write(b'\x00');count+=1
            c=restored.c;r=c.r;p=restored.spec(1,1,'static',scale);v=c.derive(p,d);signed,mag,up=c.group_specs(p,v,0);value=v['S'];width=r.derive(up,d)[3];mr=r.root(mag.source,[0]);roots=[r.root(signed.source,[0]),mr,mr,r.source_root(up,c.planes([value],1,width))];local=c.initial(p,v);states=[bytes(32)]*v['children'];expected=restored.oracle(p,[0],[scale])[1]
            with tempfile.TemporaryFile() as spool:
                c.write_group(spool,[0],[value]);c.parent(p,v,c.context(v,expected,roots,states,d),roots,local,spool,d)
                for byte in range(width,4):
                    spool.seek(1+byte);spool.write(b'\x01');restored.rejects('Replay:0:CommitmentMismatch',lambda:c.parent(p,v,c.context(v,expected,roots,states,d),roots,local,spool,d));spool.seek(1+byte);spool.write(b'\x00');count+=1
    assert count==20;print('all unused spool bytes rejected',count,flush=True)


def honest():
    digest=hashlib.sha256();count=0
    for d in (4,8):
        for scale in (1,2):
            p=weighted.spec(3,3,8810+count);p=replace(p,schema=replace(p.schema,scale=scale));S=weighted.c.derive(p,d)['constants']['restored_max'];out=weighted.run(p,[1,2,0],[0,S,2*S]*3,d);digest.update(out['state']);count+=1
            p=restored.spec(3,3,'static',scale,8820+count);out=restored.run(p,[-127,0,127]*3,[scale]*3,d);digest.update(out['state']);count+=1
            print('complete compact spool pair passed',d,scale,flush=True)
    print(json.dumps(dict(proofs=count,sha256=digest.hexdigest()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--controls':controls,'--honest':honest};assert set(sys.argv[1:])<=set(modes)
    for flag in sys.argv[1:] or modes:modes[flag]()
