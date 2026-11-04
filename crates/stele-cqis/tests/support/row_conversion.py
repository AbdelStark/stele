"""RFC-0025 §2.2/2.5 and flow §1: new native row fixtures, no campaign mains.

Python3.12, numpy==1.26.4, blake3==1.0.11, python-flint==0.9.0,
safetensors==0.6.2. 10000 randomized rows for each kind/policy pair.
"""
from hashlib import sha256
import json
from pathlib import Path
from struct import pack
import sys
import numpy as np
from blake3 import blake3

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'research/cqis-model-contract'))
from flow_bounds import Row
from check_bound_collection import record_oracle
from model_execution import convert

rng=np.random.default_rng(50540);data=bytearray();groups=[];counts={}
def oracle(p,values):
    h=1<<30 if p.kind else 32768;high=h if p.kind else h-1
    if np.any((values < -h)|(values > high)):return b'\2'
    magnitudes=np.abs(values.astype(np.int64))
    index=int(np.argmax(magnitudes));maximum=int(magnitudes[index])
    scale=p.scale if p.policy else -(-maximum//127)
    if scale:
        q=magnitudes//scale+(2*(magnitudes%scale)>=scale)
        if np.any(q>127):return b'\1'
        codes=np.where(values<0,-q,q).astype('i1')
    else:codes=np.zeros(p.d,dtype='i1')
    return pack('<BIHI',0,scale,65535 if p.policy else index,0 if p.policy else maximum)+codes.tobytes()

def group(label,p,rows,randomized=False,seed=None):
    start=len(data);count=0;outcomes={};inputs=blake3()
    for values in rows:
        values=np.asarray(values,dtype='<i4');assert values.shape==(p.d,)
        expected=oracle(p,values);inputs.update(values.tobytes())
        # Regenerate random inputs from a public fixed seed; retain every expected
        # output byte and the full input digest without checking in random payloads.
        if not randomized:data.extend(values.tobytes())
        data.extend(expected)
        outcomes[str(expected[0])]=outcomes.get(str(expected[0]),0)+1;count+=1
        # A few rows also cross-check the unchanged scalar research implementation.
        if count<=3:
            try:old=convert(tuple(map(int,values)),p.fraction,(p.policy,p.scale),bool(p.kind))
            except ValueError:assert expected[0]!=0
            else:
                assert expected[0]==0
                assert old.scale==int.from_bytes(expected[1:5],'little')
                assert bytes(x%256 for x in old.codes)==expected[11:]
                assert old.fraction==p.fraction
    raw=record_oracle(p)
    groups.append(dict(label=label,parameters=pack('<HBBBI',p.d,p.kind,p.fraction,p.policy,p.scale).hex(),
        count=count,offset=start,length=len(data)-start,record_id=blake3(raw).hexdigest(),randomized=randomized,
        seed=seed,input_id=inputs.hexdigest(),outcomes=outcomes))
    if randomized:counts[f'{p.kind}/{p.policy}']=counts.get(f'{p.kind}/{p.policy}',0)+count

for kind in (0,1):
    h=1<<30 if kind else 32768;high=h if kind else h-1;limit=8454661 if kind else 65535
    for policy in (0,1):
        for j in range(16):
            d=int(rng.integers(1,65));fraction=(44 if kind else 30) if j==0 else int(rng.integers(0,45 if kind else 31))
            scale=([1,2,3,limit][j] if j<4 else int(rng.integers(1,limit+1))) if policy else 0
            p=Row(d,kind,fraction,policy,scale)
            seed=50540+len(groups)
            def rows():
                state=seed
                for i in range(625):
                    bound=min(h,(255*scale-1)//2) if policy and i%4 else h
                    width=min(bound,high)+bound+1;values=[]
                    for _ in range(d):
                        state=(6364136223846793005*state+1442695040888963407)&((1<<64)-1)
                        values.append(-bound+(state>>32)%width)
                    yield values
            group(f'random {kind}/{policy}/{j}',p,rows(),True,seed)
        for policy_scale in ([0] if not policy else [1,2,3,limit]):
            p=Row(4,kind,44 if kind else 30,policy,policy_scale)
            group(f'endpoints {kind}/{policy}/{policy_scale}',p,[[0]*4,[-h,high,0,1],[0,-127,127,126],[-1,0,1,0]])
        p=Row(16384,kind,44 if kind else 30,policy,limit if policy else 0)
        group(f'full width {kind}/{policy}',p,[np.zeros(16384,dtype=np.int32),np.resize(np.array([-h,high,0,1],dtype=np.int32),16384)])
    for scale in ([2,4,65534] if not kind else [2,65536,8454660]):
        for q in (0,1,126,127):
            value=q*scale+scale//2
            if value<=high:group(f'tie {kind}/{scale}/{q}',Row(2,kind,0,1,scale),[[value,-value]])

group('gated input endpoints',Row(1,1,44,0,0),[[v] for v in (-(1<<31),-(1<<30)-1,1<<30,(1<<30)+1,(1<<31)-1)])
group('gated scale high bytes',Row(3,1,44,1,65537),[[65537*127,-65537*127,65537]])
assert counts=={'0/0':10000,'0/1':10000,'1/0':10000,'1/1':10000}
out=ROOT/'crates/stele-cqis/tests/fixtures';raw=bytes(data);(out/'row-conversion.bin').write_bytes(raw)
names=['flow_bounds.py','check_bound_collection.py','model_execution.py']
receipt=dict(seed=50540,randomized=counts,groups=groups,fixture_sha256=sha256(raw).hexdigest(),
 sources={'research/cqis-model-contract/'+name:sha256((ROOT/'research/cqis-model-contract'/name).read_bytes()).hexdigest() for name in names})
(out/'row-conversion.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
print(json.dumps(dict(randomized=counts,groups=len(groups),cases=sum(g['count'] for g in groups),bytes=len(raw))))
