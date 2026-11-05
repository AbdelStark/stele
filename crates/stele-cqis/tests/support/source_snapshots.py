"""RFC-0025 source §4: independent SHA-256 fixtures for bounded file snapshots."""
from hashlib import sha256
import json
from pathlib import Path
from random import Random

rng=Random(50380)
lengths=[0,1,2,55,56,63,64,65,127,128,255,256,4095,65535,65536,65537,131071,131072,131073,5242881]
lengths += [rng.randrange(200000) for _ in range(32)]
cases=[]
for length in lengths:
    seed=rng.randrange(256);h=sha256()
    for start in range(0,length,65536):
        h.update(bytes(((i*17)^(i>>8)^(i>>16)^(i>>24)^seed)&255 for i in range(start,min(length,start+65536))))
    cases.append(dict(length=length,seed=seed,sha256=h.hexdigest()))
out=Path(__file__).resolve().parents[1]/'fixtures/source-snapshots.json'
out.write_text(json.dumps(dict(seed=50380,cases=cases),separators=(',',':'))+'\n')
print(json.dumps(dict(cases=len(cases),maximum_length=max(lengths))))
