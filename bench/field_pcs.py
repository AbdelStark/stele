"""RFC-0010 A9 §6 / RFC-0018 §1: bounded complete native PCS/A1 resource ledgers."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CELLS = [('primitive', ell, m, b, d) for ell,m in ((0,0),(2,1),(4,12),(12,4))
         for b in (1,2) for d in (4,8)] + [('a1',2,1,b,d) for b in (1,2) for d in (4,8)]
CASES = [(*cell,sample) for cell in CELLS for sample in range(3)]
HASH_KEYS = {'hash_evaluations','xof_requests','xof_bytes','state_updates','candidate_words','column_attempts'}


@lru_cache(None)
def policy(m,b):
    n,c = 1 << (m+b), 1 << m
    distance = n if c == 1 else n-c
    radius = (distance-1)//3
    def least(numerator):
        q=1
        while (1 << 130)*numerator**q > n**q:
            q+=1
        return q
    return least(n-radius-1),least(n-distance+radius)


def integers(value):
    if isinstance(value, dict):
        for v in value.values(): integers(v)
    elif isinstance(value, list):
        for v in value: integers(v)
    elif isinstance(value, (int,float)):
        assert type(value) is int and 0 <= value < 1 << 64
    else:
        assert value is None or isinstance(value,str)


def hex_bytes(value,n):
    assert isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(2*n)+'}',value)
    return bytes.fromhex(value)


def hashes(h,local=None):
    assert set(h)==HASH_KEYS
    if local is not None:
        assert h == dict.fromkeys(HASH_KEYS,0) | {'hash_evaluations':local}


def decode(text):
    def unique(pairs):
        assert len(pairs)==len(dict(pairs)), 'duplicate JSON keys'
        return dict(pairs)
    return json.loads(text,object_pairs_hook=unique)


def receipt(v,mode,ell,m,b,d):
    integers(v)
    assert set(v)=={'mode','ell','m','blowup','degree','source_count','sources','openings','a1',
                    'consumer_usage','producer_continuation','consumer_continuation','stages_ns',
                    'total_ns','remainder_ns'}
    assert (v['mode'],v['ell'],v['m'],v['blowup'],v['degree'])==(mode,ell,m,b,d)
    count,opened = (3,3) if mode=='a1' else (1,2)
    assert v['source_count']==count and len(v['sources'])==count and len(v['openings'])==opened
    stages={'fixture','prepare','certificate_prove','certificate_verify','transcripts',
            'coefficients','opening_prove','validation'}
    stages |= {'a1_setup','a1_prove','a1_replay','closed_verify'} if mode=='a1' else {'opening_verify'}
    assert set(v['stages_ns'])==stages
    assert all(v['stages_ns'][s]>0 for s in ('prepare','certificate_prove','certificate_verify',
               'opening_prove','closed_verify' if mode=='a1' else 'opening_verify'))
    assert v['total_ns']>=sum(v['stages_ns'].values())>0
    assert v['remainder_ns']==v['total_ns']-sum(v['stages_ns'].values())
    r,c,n,h = 1<<ell,1<<m,1<<(m+b),m+b
    qc,qo=policy(m,b)
    length=lambda q:1+4*d*c+q*(4*r+32*h)
    for i,source in enumerate(v['sources']):
        assert set(source)=={'id','source_bytes','certificate_id','certificate_bytes','certificate_capacity_bytes',
            'certificate_digest','certificate_prove','certificate_verify','preparation_hashes','input_capacity_bytes',
            'queries_certificate','queries_opening','preparation'}
        assert source['id']==41+i
        encoded=hex_bytes(source['source_bytes'],105)
        assert encoded[:23]==b'stele/v0.1/field-source' and encoded[23:25]==bytes([1,d])
        assert int.from_bytes(encoded[25:33],'little')==41+i and encoded[33]==ell
        assert encoded[53:55]==bytes([m,b]) and encoded[71:73]==bytes([0,1])
        assert int.from_bytes(encoded[55:63],'little')==r and int.from_bytes(encoded[63:71],'little')==c
        hex_bytes(source['certificate_id'],32);hex_bytes(source['certificate_digest'],32)
        assert (source['queries_certificate'],source['queries_opening'])==(qc,qo)
        assert source['certificate_bytes']==length(qc)
        assert source['certificate_capacity_bytes']>=length(qc) and source['input_capacity_bytes']>=4*r*c
        w=source['preparation']
        assert set(w)=={'borrowed_message_bytes','encoded_columns_bytes','encoder_peak_bytes',
                        'leaf_references_bytes','merkle_nodes_bytes','peak_owned_bytes'}
        assert w['borrowed_message_bytes']==4*r*c and w['encoded_columns_bytes']>=4*r*n
        assert w['merkle_nodes_bytes']>=32*(2*n-1) and w['leaf_references_bytes']>=16*n
        assert w['encoder_peak_bytes']>=4*n
        assert w['peak_owned_bytes']==w['encoded_columns_bytes']+max(w['encoder_peak_bytes'],
            w['leaf_references_bytes']+w['merkle_nodes_bytes'])
        hashes(source['preparation_hashes'],2*n-1)
        hashes(source['certificate_prove']);hashes(source['certificate_verify']['local'],qc*(1+h)+1)
        assert source['certificate_prove']==source['certificate_verify']['transcript']
        u=source['certificate_prove']
        assert u['column_attempts']>=qc and u['xof_requests']==ell+u['column_attempts']
        assert u['hash_evaluations']==u['xof_requests']+4
    for i,opening in enumerate(v['openings']):
        assert set(opening)=={'id','queries','certificate_id','bytes','capacity_bytes','digest'} | (
            {'producer_usage','verifier_usage'} if mode=='primitive' else set())
        source=v['sources'][i if mode=='a1' else 0]
        assert opening['id']==(41+i if mode=='a1' else 100+i)
        assert opening['certificate_id']==source['certificate_id'] and opening['queries']==qo
        assert opening['bytes']==length(qo) and opening['capacity_bytes']>=length(qo)
        hex_bytes(opening['digest'],32)
        if mode=='primitive':
            hashes(opening['producer_usage']['local'],0)
            hashes(opening['verifier_usage']['local'],qo*(1+h))
            assert opening['producer_usage']['transcript']==opening['verifier_usage']['transcript']
    hashes(v['consumer_usage']['local'],opened*qo*(1+h))
    hashes(v['consumer_usage']['transcript'])
    assert v['consumer_usage']['transcript']['column_attempts']>=opened*qo
    assert hex_bytes(v['producer_continuation'],4*d)==hex_bytes(v['consumer_continuation'],4*d)
    if mode=='a1':
        a=v['a1']; rounds=ell+m
        assert set(a)=={'bundle_bytes','bundle_digest','instance_bytes','instance_digest','message_bytes',
                       'message_digest','rounds','finals','replay_usage','opening_producer_snapshots','sc'}
        assert a['bundle_bytes']==12+137*count and a['instance_bytes']==57+12*d
        assert (a['rounds'],a['finals'],a['message_bytes'])==(rounds,count,rounds*(12+8*d)+12+4*d*count)
        assert a['sc']==dict(id=71,m=rounds,degree=1,field_degree=d,numerator=rounds)
        hex_bytes(a['message_digest'],32);hex_bytes(a['bundle_digest'],32);hex_bytes(a['instance_digest'],32)
        hashes(a['replay_usage']);assert a['replay_usage']['xof_requests']==rounds
        assert len(a['opening_producer_snapshots'])==count
        snapshots=a['opening_producer_snapshots']
    else:
        assert v['a1'] is None
        snapshots=[o['producer_usage'] for o in v['openings']]
    previous=a['replay_usage'] if mode=='a1' else dict.fromkeys(HASH_KEYS,0)
    for snapshot in snapshots:
        hashes(snapshot['local'],0);hashes(snapshot['transcript'])
        assert all(snapshot['transcript'][k]>=previous[k] for k in HASH_KEYS)
        assert snapshot['transcript']['column_attempts']-previous['column_attempts']>=qo
        previous=snapshot['transcript']
    assert previous==v['consumer_usage']['transcript']


def check_cases(records):
    assert [(r['mode'],r['ell'],r['m'],r['blowup'],r['degree'],r['sample']) for r in records]==CASES


def run(*args):
    return subprocess.check_output(args,cwd=ROOT,text=True).strip()


def main():
    if len(sys.argv)!=2 or (platform.system(),platform.machine())!=('Darwin','arm64'):
        raise SystemExit('usage on arm64 macOS: uv run --python 3.12 bench/field_pcs.py <new-ledger.json>')
    output=Path(sys.argv[1]).absolute(); raw=output.with_suffix('.samples')
    if output.exists() or raw.exists() or run('git','status','--porcelain'):
        raise SystemExit('requires clean committed source and new output/sample paths')
    commit,tree=run('git','rev-parse','HEAD'),run('git','rev-parse','HEAD^{tree}')
    def unchanged():
        assert run('git','rev-parse','HEAD')==commit and run('git','rev-parse','HEAD^{tree}')==tree
        assert not run('git','status','--porcelain'),'sources changed during measurement'
    plan=dict(cases=CASES,workers=1,samples_per_cell=3,build='release',
        sampling='no warmup, cache flush, retries or discarded samples; fixed case order',
        fixture='M[s][i]=(37*i+101*s+9) mod p; coefficient limb[k]=37*seed+17*k+9; '
                'primitive a seed=i+opening+1, b seed=i+opening+7; A1 coefficient seed=17',
        statement='conditional Circle certificates and functional openings; A1 id71, originals41/42/43, '
                  'P=coefficient*input0+0*input2 (input1 unused); every original is opened',
        timing='inclusive native fixture/preparation/registration, coefficients, production, actual consumers, '
               'continuations, receipt observations and protocol buffer cleanup; A1 includes full point replay; '
               'excludes build, process launch, argument parsing and receipt JSON serialization',
        memory='fresh-worker whole-pipeline peak RSS, including source/prepared trees, retained certificates/proofs, '
               'encoder scratch/twiddles, all consumers, stack, runtime and allocator retention; not isolated verifier RSS',
        capacities='actual PreparationWork and caller proof/input capacities only; not a complete PCS/A1 owned-vector peak; '
                   'never sum separate stage peaks; both primitive proofs retained through the second consumer',
        usage='cumulative shared-transcript snapshots retained separately from per-call Merkle work; '
              'registration and A1 replay have distinct transcripts; no adversarial caps or loss probabilities',
        proof_sizes='separate canonical certificate/opening bytes and A1 message payloads/public framing; no inference container',
        correctness='each measured proof fully consumed natively; receipt checks exact shapes, query counts, wire sizes, '
                    'original records and continuation; independent byte parity/all59 policies/negative controls remain task gates',
        scope='bounded CPU micro measurements with all named consumers active; standard schema tag only; no profile, '
              'inference, privacy, fit, speedup or one-weight-pass claim; concurrent original research workers left running')
    raw.mkdir(parents=True)
    metadata=dict(commit=commit,tree=tree,plan=plan,toolchain=run('rustc','-Vv'),os=platform.platform(),
                  cargo=run('cargo','--version'),python=sys.version,
                  device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'))
    (raw/'provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    build=['cargo','build','-p','stele-negative-controls','--example','field_pcs_bench','--release','--locked','--offline']
    with (raw/'build.log').open('x') as stream:
        subprocess.run(build,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,check=True)
    binary=ROOT/'target/release/examples/field_pcs_bench'
    metadata['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
    (raw/'provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    unchanged()
    records=[]
    for index,case in enumerate(CASES):
        mode,ell,m,b,d,sample=case; unchanged()
        stats=raw/f'{index:02d}.time.txt'
        result=subprocess.run(['/usr/bin/time','-l','-o',str(stats),str(binary),*map(str,case[:-1])],
                              cwd=ROOT,text=True,capture_output=True)
        (raw/f'{index:02d}.stdout').write_text(result.stdout)
        (raw/f'{index:02d}.stderr').write_text(result.stderr)
        (raw/f'{index:02d}.exit').write_text(str(result.returncode)+'\n')
        result.check_returncode(); unchanged()
        v=decode(result.stdout);receipt(v,mode,ell,m,b,d)
        report=stats.read_text()
        peaks=[int(line.split()[0]) for line in report.splitlines() if 'maximum resident set size' in line]
        assert len(peaks)==1 and peaks[0]>0
        records.append(dict(**v,sample=sample,peak_rss_bytes=peaks[0],native_time_resource_report=report))
        print(f'Validated {case}',flush=True)
    check_cases(records);unchanged()
    # Repeat samples must retain identical statements, proofs, records and continuations.
    for start in range(0,len(records),3):
        identity=lambda v:(v['sources'],v['openings'],v['a1'],v['consumer_usage'],v['consumer_continuation'])
        assert identity(records[start])==identity(records[start+1])==identity(records[start+2])
    data=dict(schema_version=1,kind='micro',workload='micro/conditional-field-pcs',commit=commit,
        toolchain=metadata['toolchain'],device=metadata['device'],driver='not-applicable',
        model_config=dict(**metadata,samples=records),
        plan_digest=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard',bindings_all_on=True,batch_size=1,prompt_tokens=0,generated_tokens=0,
        prover_time_ns=sum(r['total_ns'] for r in records),witness_recompute_ns=0,
        stage_times_ns={f'{i}/{s}':n for i,r in enumerate(records)
                        for s,n in (r['stages_ns'] | {'remainder':r['remainder_ns']}).items()},
        kernel_counters={},proof_size_bytes=0,verifier_time_ns=dict(rust=0,python=0),
        controls=dict(total=0,passed=0,failed=0),
        note='Complete native registration plus two ordinary openings, and actual three-original A1 closure. '
             'All samples retained; inclusive cleanup/replay cost and fresh-worker whole-pipeline RSS. '
             'Component sizes/times live in model_config; root inference fields are zero. No profile admission or fitted constant.')
    with output.open('x') as stream:json.dump(data,stream,indent=2);stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],
                   cwd=ROOT,check=True)


if __name__=='__main__':
    main()
