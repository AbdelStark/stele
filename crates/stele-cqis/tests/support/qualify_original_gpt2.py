"""Manual complete original GPT-2-small preparation qualification, not a benchmark.

Python 3.12, numpy==1.26.4, blake3==1.0.11, python-flint==0.9.0,
safetensors==0.6.2. Uses qualified pure helpers, never historical campaign mains.
Original files must already exist at the immutable revision pinned below.
"""
import argparse
from dataclasses import replace
from fractions import Fraction as Q
from hashlib import sha256
import json
from pathlib import Path
from random import Random
from struct import pack, unpack
import subprocess
import sys
import numpy as np
from blake3 import blake3

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'research/cqis-model-contract'))
from check_model_codec import roles, oracle as model_frame
from check_artifact_codec import preparation, configurations
from check_source_architecture import mapped
from check_registry_codec import oracle as registry_frame
from check_bound_collection import expected_records, record_oracle
from check_scales_codec import oracle as scales_frame
from function_bounds import Activation, Exponential
from model_codec import Model, Block, encode as encode_model
from numerics import LayerNorm
from scales_codec import Scale
from source_map import Shape
import source_architecture
import source_codec as sc

REVISION='607a30d783dfa663caf39e06633721c8d4cfcd7e'
PINS={
 'model.safetensors':'248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707',
 'config.json':'0daed7749b4f02b8f76240d5444551d7b08712dab4d0adb8239c56ba823bb7b4',
 'generation_config.json':'ed0b32ac72c0f5f44a719abb2d7786ea5146c871f83717b7f2018065954de02b',
 'tokenizer.json':'8414cab924d8b9b33013f0d221c5862f365ee9be39c5c2bfae8a5a9e970478a6',
 'vocab.json':'196139668be63f3b5d6574427317ae82f612a97c5d1cdaf36ed2256dbf636783',
 'merges.txt':'1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5',
 'tokenizer_config.json':'5e04eb606e3a1583530a42e36c2a6b6615c86f34fe77e44d9ddeb43ff940931f',
}

def digest(path):
    h=sha256()
    with path.open('rb') as stream:
        while raw:=stream.read(1<<20):h.update(raw)
    return h.hexdigest()

def configuration(weight_bits=8):
    # Explicit offline qualification parameters, not calibrated fidelity defaults.
    assert weight_bits in (4,8)
    s=Shape(0,12,768,12,12,64,3072,50257,1024)
    norm=LayerNorm(768,7,8,7,8,1,100000)
    b=Block(norm,norm,(7,)*6,7,7,7,((0,0),)*7,1,-3,0,0,
            Exponential(1024,15,7,14,0),Activation(3072,4,7,7),None)
    formats=tuple((weight_bits,0) if len(ds)==2 else (16,8) for _,_,ds in roles(s))
    model=Model(s,formats,7,(b,)*12,norm,(0,0),7,None)
    mapping=mapped(model,0,Random(50520))
    mapping=replace(mapping,entries=tuple(replace(e,dtype=3) for e in mapping.entries),aliases=())
    return model,mapping

def exact(word):
    word=int(word);exponent=(word>>23)&255;assert exponent!=255
    n=(word&0x7fffff)+(1<<23 if exponent else 0)
    return (-1 if word>>31 else 1)*Q(n)*Q(2)**(exponent-150 if exponent else -149)

def rounded(words,mantissa,exponent,minimum,maximum):
    """Exact finite F32 divided by mantissa*2^exponent; all arrays stay integer."""
    encoded=(words>>23)&255
    assert not np.any(encoded==255),'Nonfinite'
    n=((words&0x7fffff)|np.where(encoded==0,0,1<<23)).astype(np.uint64)
    power=np.where(encoded==0,-149,encoded.astype(np.int64)-150)-exponent
    # Any nonzero positive shift >=40 exceeds either code domain even at m=65535.
    assert not np.any((power>=40)&(n!=0)),'Overflow'
    numerator=n<<np.clip(power,0,39).astype(np.uint64)
    # For shift>=25, n<2^24 implies rounding to zero for every positive mantissa.
    denominator=np.asarray(mantissa,dtype=np.uint64)<<np.clip(-power,0,25).astype(np.uint64)
    q=numerator//denominator+((numerator%denominator)*2>=denominator)
    signed=np.where(words>>31,-q.astype(np.int64),q.astype(np.int64))
    assert np.all((minimum<=signed)&(signed<=maximum)),'Overflow'
    return signed

def check_rounding():
    rng=Random(50521);words=[];ms=[];es=[];expected=[]
    for _ in range(10000):
        word=rng.getrandbits(32)
        if (word>>23)&255==255:word^=1<<23
        m=rng.randint(1,65535);value=exact(word)
        e=value.numerator.bit_length()-value.denominator.bit_length()-8+rng.randrange(8) if value else 0
        ratio=value/(m*Q(2)**e);n,d=abs(ratio.numerator),ratio.denominator
        result=(n//d+(2*(n%d)>=d))*(-1 if ratio<0 else 1)
        words.append(word);ms.append(m);es.append(e);expected.append(result)
    actual=rounded(np.array(words,dtype=np.uint32),np.array(ms,dtype=np.uint64),
                   np.array(es,dtype=np.int64),-32768,32767)
    assert actual.tolist()==expected

def packed(codes,bits):
    if bits==8:return codes.astype('i1').tobytes(order='C')
    assert bits==4 and np.all((-7<=codes)&(codes<=7))
    digits=(codes.reshape(-1)&15).astype(np.uint8)
    if len(digits)%2:digits=np.append(digits,np.uint8(0))
    return (digits[::2]|(digits[1::2]<<4)).tobytes()

def check_packing():
    for lo in range(-7,8):
        assert packed(np.array([lo],dtype=np.int64),4)==bytes((lo%16,))
        for hi in range(-7,8):
            assert packed(np.array([lo,hi],dtype=np.int64),4)==bytes((lo%16+16*(hi%16),))
    values=np.arange(-7,8,dtype=np.int64).reshape(3,5)
    flat=list(range(-7,8))+[0]
    assert packed(values,4)==bytes(flat[i]%16+16*(flat[i+1]%16) for i in range(0,16,2))
    assert packed(values,8)==bytes(x%256 for x in range(-7,8))

def verify_artifact(model,mapping,source_path,artifact_path):
    with source_path.open('rb') as stream:
        header_length=unpack('<Q',stream.read(8))[0];header=json.loads(stream.read(header_length))
    header.pop('__metadata__',None)
    assert set(header)=={e.name for e in mapping.entries}|set(mapping.ignored)
    source=np.memmap(source_path,mode='r',dtype=np.uint8);scales=[];count=0;h=blake3()
    with artifact_path.open('rb') as actual:
        def emit(raw):
            assert actual.read(len(raw))==raw,('ArtifactMismatch',actual.tell())
            h.update(raw)
        emit(b'cqis-weights-v1'+blake3(preparation(model,mapping)).digest()+pack('<H',196))
        for ordinal,(entry,(_,_,dims),(bits,fraction),ci) in enumerate(zip(mapping.entries,roles(model.shape),model.formats,configurations(model))):
            d=header[entry.name];assert d['dtype']=='F32' and tuple(d['shape'])==entry.shape
            values=np.ndarray(entry.shape,dtype='<u4',buffer=source,offset=8+header_length+d['data_offsets'][0])
            if entry.transform==1:values=values.T
            elif entry.transform==2:values=values[:,entry.part*dims[0]:(entry.part+1)*dims[0]].T
            elif entry.transform==3:values=values[entry.part*dims[0]:(entry.part+1)*dims[0]]
            assert values.shape==dims
            parts=[b'stele/v0.1/cqis/tensor',pack('<I',len(ci)),ci]
            if len(dims)==2:
                q=(1<<(bits-1))-1
                peaks=[]
                for start in range(0,dims[0],128):
                    words=values[start:start+128];assert not np.any(((words>>23)&255)==255)
                    peaks.extend(np.max(words&0x7fffffff,axis=1).tolist())
                maximum=exact(max(peaks));e=0
                if maximum:
                    e=maximum.numerator.bit_length()-maximum.denominator.bit_length()-(q*65535).bit_length()+1
                    while maximum>q*65535*Q(2)**e:e+=1
                    while maximum<=q*65535*Q(2)**(e-1):e-=1
                ms=[]
                for peak in peaks:
                    ratio=exact(peak)/(q*Q(2)**e)
                    ms.append(max(1,-(-ratio.numerator//ratio.denominator)))
                assert all(1<=m<=65535 for m in ms)
                scale=Scale(e,pack('<'+'H'*len(ms),*ms));scales.append(scale)
                parts.extend((pack('<h',e),scale.mantissas))
            size=(int(values.size)*bits+7)//8;parts.append(pack('<Q',size));metadata=b''.join(parts)
            emit(pack('<Q',len(metadata)+size)+metadata)
            for start in range(0,dims[0],128):
                words=values[start:start+128]
                if len(dims)==2:
                    mantissa=np.array(ms[start:start+128],dtype=np.uint64)[:,None]
                    codes=rounded(words,mantissa,e,-q,q)
                    # Every nonfinal 128-row chunk contains an even number of codes.
                    assert start+len(words)==dims[0] or words.size%2==0
                    payload=packed(codes,bits)
                else:payload=rounded(words,1,-fraction,-32768,32767).astype('<i2').tobytes(order='C')
                emit(payload);count+=int(words.size)
            if ordinal%16==0:print(json.dumps({'verified_physical_record':ordinal,'scalars':count}),flush=True)
        assert actual.read(1)==b'','ArtifactSuffix'
    return tuple(scales),h.hexdigest(),count

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source-dir','native','output-dir'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--weight-bits',type=int,choices=(4,8),default=8)
    args=parser.parse_args();root=args.output_dir.resolve();root.mkdir(exist_ok=False)
    inputs=root/'inputs';inputs.mkdir();native=args.native.resolve(strict=True);source_dir=args.source_dir.resolve(strict=True)
    checked={name:sc.File(name,(source_dir/name).stat().st_size,bytes.fromhex(expected)) for name,expected in PINS.items()}
    for name,expected in PINS.items():assert digest(source_dir/name)==expected,('OriginalFile',name)
    model,mapping=configuration(args.weight_bits);mr=model_frame(model);assert mr==encode_model(model)
    source=sc.Source(0,None,(checked['model.safetensors'],))
    assets=sc.Assets(checked['config.json'],tuple(checked[n] for n in sorted(PINS) if n not in ('model.safetensors','config.json','generation_config.json')),checked['generation_config.json'])
    frames={'model.bin':mr,'preparation.bin':preparation(model,mapping),'source.bin':sc.encode_source(source),'assets.bin':sc.encode_assets(assets)}
    for name,raw in frames.items():(inputs/name).write_bytes(raw)
    sources=sorted((ROOT/'crates/stele-cqis/src').rglob('*.rs'))+[ROOT/'crates/stele-cqis/examples/prepare_source.rs',Path(__file__).resolve(),ROOT/'Cargo.lock']
    pins={str(p.relative_to(ROOT)):digest(p) for p in sources}
    receipt=dict(repository='openai-community/gpt2',revision=REVISION,original_files=PINS,source_pins=pins,native_sha256=digest(native),
        head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),weight_bits=args.weight_bits,
        parameters=f'Explicit int{args.weight_bits} matrices, vector G=8, activation/residual F=7, exact accumulation, greedy; no calibration/fidelity claim.')
    (root/'inputs.json').write_text(json.dumps(receipt,indent=2)+'\n')
    with (root/'native.stdout').open('xb') as out,(root/'native.stderr').open('xb') as err:
        print('starting native complete original preparation',flush=True)
        subprocess.run([str(native),*(str(inputs/n) for n in frames),'0',str(source_dir),str(root/'native')],stdout=out,stderr=err,check=True)
    result=root/'native';check_rounding();check_packing()
    scales,artifact_id,count=verify_artifact(model,mapping,source_dir/'model.safetensors',result/'artifact.bin')
    assert (result/'scales.bin').read_bytes()==scales_frame(model,scales)
    auxiliary={name:(source_dir/name).read_bytes() for name in PINS if name!='model.safetensors'}
    assert (result/'source-config.bin').read_bytes()==source_architecture.binding(model,mapping,0,assets,auxiliary)
    rr=registry_frame(model);assert (result/'registry.bin').read_bytes()==rr
    records=expected_records(model,scales);bound_hash=blake3()
    with (result/'bounds.bin').open('rb') as actual:
        def compare(raw):assert actual.read(len(raw))==raw;bound_hash.update(raw)
        compare(b'stele/v0.1/cqis/bounds'+b''.join(blake3(raw).digest() for raw in (mr,scales_frame(model,scales),rr))+pack('<H',len(records)))
        for ordinal,(_,_,parameters) in enumerate(records):
            raw=record_oracle(parameters);compare(pack('<HI',ordinal,len(raw))+raw)
        assert actual.read(1)==b''
    identity=b'stele/v0.1/cqis/identity'+b''.join(blake3(raw).digest() for raw in (mr,scales_frame(model,scales),rr))+bound_hash.digest()
    assert (result/'identity.bin').read_bytes()==identity
    reported=json.loads((result/'result.json').read_text());assert reported['digest_cqis']==artifact_id and reported['cqis_id']==blake3(identity).hexdigest()
    assert all(digest(ROOT/name)==expected for name,expected in pins.items()),'SourceChanged'
    receipt.update(status='passed',native_result=reported,selected_scalars=count,rounding_reference_cases=10000,
        artifacts={p.name:digest(p) for p in sorted(result.iterdir())},
        boundary='Complete original-source numerical preparation and every-byte independent parity; no inference, tokenizer execution, fidelity, passport, proof, PCS/ZK or profile credit.')
    (root/'results.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':'passed','selected_scalars':count,'digest_cqis':artifact_id,'cqis_id':reported['cqis_id']}),flush=True)

if __name__=='__main__':
    if not __debug__:raise RuntimeError('reference assertions must remain enabled')
    main()
