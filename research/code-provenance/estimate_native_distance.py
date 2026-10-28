# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0010 A4: check native distance witnesses independently; upper observations only."""
from pathlib import Path
import json
import subprocess
from sampler import materialize, manifest
from check_recursive import dense_word, base_generator
from recursive import sc

def estimates():
    root=Path(__file__).resolve().parents[2]
    run=subprocess.run(['cargo','run','-q','-p','stele-code','--release','--example','distance_estimate','--locked','--offline'],cwd=root,text=True,capture_output=True,check=True)
    records=[json.loads(line) for line in run.stdout.splitlines()]
    assert [(r['j'],r['seed']) for r in records]==[(j,s) for j in (3,4) for s in (0,1)]
    base=base_generator()
    for r in records:
        n=4**r['j']; kind=r['witness_kind']; index=r['witness_index']; row=[0]*n
        assert r['samples']==2*n-1+32 and kind in (0,1,2)
        if kind==0: row[index]=1
        elif kind==1: row[index]=1; row[index+1]=sc.P-1
        else:
            state=index+1
            for i in range(n):
                state=(state*6364136223846793005+1)%(1<<64);row[i]=(state>>32)%sc.P
            row[0]=1
        setup,_=materialize(manifest(bytes([r['seed']])*32,r['j']))
        word=dense_word(setup,[(v,) for v in row],base)
        assert any(row) and sum(v!=(0,) for v in word)==r['distance_upper_bound']>0
    return records
if __name__=='__main__':
    print(json.dumps({'scope':'Sampled upper bounds, not distance certificates or profile parameters','records':estimates()},sort_keys=True))
