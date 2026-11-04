"""RFC-0025: bounded original-byte preparation fixtures; no campaign entry points.

Python 3.12, blake3==1.0.11, safetensors==0.6.2, python-flint==0.9.0.
Independent conversion, Registry and static-record oracles cover full small models.
These fixtures do not qualify original named checkpoints or proof consumers.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack
import sys
from blake3 import blake3

root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(root/'research/cqis-model-contract'))
from check_preparation_execution import case
from check_artifact_codec import preparation
from check_model_codec import oracle as model_frame
from check_scales_codec import oracle as scales_frame
from check_source_conversion import oracle as conversion_oracle
from check_registry_codec import oracle as registry_frame
from check_bound_collection import expected_records, record_oracle
import source_architecture
import source_codec

rng=Random(50500);data=bytearray();spans={};cases=[]
def store(raw):
    if raw not in spans:spans[raw]=dict(offset=len(data),length=len(raw));data.extend(raw)
    return spans[raw]

for i in range(6):
    kind=i%3;dtype=1+i%4;groups=1 if i<3 else 3
    m,mp,ts,src,assets,files=case(rng,kind,dtype,groups)
    # These new small fixtures use equal activation units. The fixed-256-bit
    # independent table oracle cannot resolve unequal-unit GELU tail half ties.
    # No original checkpoint/configuration or qualified corpus is changed.
    m=replace(m,blocks=tuple(replace(b,activation=replace(b.activation,E=b.activation.F)) for b in m.blocks))
    mr=model_frame(m);scales,artifact=conversion_oracle(m,mp,ts);sr=scales_frame(m,scales)
    auxiliary={f.name:files[f.name] for f in source_codec._asset_files(assets)}
    config=source_architecture.binding(m,mp,kind,assets,auxiliary)
    rr=registry_frame(m);records=expected_records(m,scales)
    bounds=blake3(b'stele/v0.1/cqis/bounds'+b''.join(blake3(raw).digest() for raw in (mr,sr,rr))+pack('<H',len(records)))
    length=120
    for ordinal,(_,_,parameters) in enumerate(records):
        raw=record_oracle(parameters);frame=pack('<HI',ordinal,len(raw))+raw
        bounds.update(frame);length+=len(frame)
    numerical=b'stele/v0.1/cqis/identity'+b''.join(blake3(raw).digest() for raw in (mr,sr,rr))+bounds.digest()
    changed=dict(auxiliary);changed['config.json']=auxiliary['config.json'].replace(b'0.00001',b'0.00002')
    assert changed['config.json']!=auxiliary['config.json']
    wrong_assets=source_codec.describe_assets('config.json',('tokenizer.json',),None,changed)
    try:source_architecture.binding(m,mp,kind,wrong_assets,changed)
    except ValueError as failure:assert str(failure)=='Epsilon'
    else:raise AssertionError('changed epsilon accepted')
    cases.append(dict(layout=kind,dtype=dtype,shards=groups,model=store(mr),preparation=store(preparation(m,mp)),
        source=store(source_codec.encode_source(src)),assets=store(source_codec.encode_assets(assets)),
        source_config=store(config),scales=store(sr),artifact=store(artifact),registry=store(rr),
        bounds_id=bounds.hexdigest(),bounds_bytes=length,identity=store(numerical),cqis_id=blake3(numerical).hexdigest(),
        files=[dict(name=name,raw=store(raw)) for name,raw in sorted(files.items())],
        wrong_assets=store(source_codec.encode_assets(wrong_assets)),wrong_config=store(changed['config.json'])))
    print(json.dumps(dict(case=i,layout=kind,dtype=dtype,shards=groups,records=len(records))),flush=True)

out=root/'crates/stele-cqis/tests/fixtures'
binary=bytes(data);(out/'preparation-pipeline.bin').write_bytes(binary)
names=['check_preparation_execution.py','check_artifact_codec.py','check_model_codec.py','check_scales_codec.py',
       'check_source_conversion.py','check_registry_codec.py','check_bound_collection.py','source_architecture.py','source_codec.py']
receipt=dict(seed=50500,cases=cases,fixture_sha256=sha256(binary).hexdigest(),
    sources={'research/cqis-model-contract/'+name:sha256((root/'research/cqis-model-contract'/name).read_bytes()).hexdigest() for name in names})
(out/'preparation-pipeline.json').write_text(json.dumps(receipt,separators=(',',':'))+'\n')
