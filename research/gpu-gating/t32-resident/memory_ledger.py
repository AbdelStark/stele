"""Replay a public E16-40z T32 archive against its frozen plan and CUDA pool receipts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("archive", type=Path)
parser.add_argument("receipt", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[3]
baseline_name = 'e16-40y-t32-compact-lookup-h100.json'
baseline = json.loads((repo/'bench/ledger'/baseline_name).read_text())
verified = json.loads(args.receipt.read_text())
def digest(data):
    return hashlib.sha256(data).hexdigest()

archive = args.archive
assert digest(archive.read_bytes()) == verified['archive_sha256']
assert verified['job'].isdecimal()
with tarfile.open(archive) as t:
    raw = {}
    for m in t.getmembers():
        assert m.isfile() and m.size < 40_000_000 and m.name not in raw
        raw[m.name]=t.extractfile(m).read()
assert len(raw) == verified['files'] and raw['stage/commit.txt'].decode().strip() == verified['source']
pins = dict((name, sha) for sha,name in (row.split() for row in raw['stage/SHA256SUMS'].decode().splitlines()))
assert pins['source.tar.gz'] == verified['source_sha256']
assert pins['commit.txt'] == digest(raw['stage/commit.txt'])
assert pins['campaign.sbatch'] == digest(raw['stage/campaign.sbatch'])
result = json.loads(raw['run/result.json'])
assert result['job'] == verified['job'] and result['inputs'] == baseline['model_config']['inputs']
assert result['proof_sha256'] == verified['proof_sha256']
assert raw['run/verify.out'].splitlines()[-1] == b'YES'
assert raw['run/wrong.out'].splitlines()[-1] == b'NO: model differs from --expect-model'
log = raw['run/prove.err'].decode()
st = runpy.run_path(str(repo/'research/gpu-gating/t32-resident/receipt.py'))['summarize'](log)
device = runpy.run_path(str(repo/'research/gpu-gating/t32-resident/test_memory.py'))['check_memory'](log)
assert st == result['stages']
shapes = [m.groups() for line in log.splitlines() if (m:=re.match(r'^shape (gkr_\w+) field=\d+ vars=(\d+) .* compact=([01])$',line))]
assert len(shapes) == len(device) == 385
compact_count = compact_ns = 0
for row,(kind,n,compact) in zip(device.values(),shapes):
    assert row['variables'] == int(n)
    if compact == '1':
        assert kind=='gkr_leaf'
        compact_count+=1
        compact_ns+=row['cpu_factors_ns']
assert compact_count == 21
gnu = raw['run/prove.time'].decode()
seconds = re.search(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([\d:.]+)',gnu)[1]
wall=0.
for part in seconds.split(':'):
    wall=60*wall+float(part)
rss=int(re.search(r'Maximum resident set size \(kbytes\): (\d+)',gnu)[1])*1024
charged = st['gkr']['charged']
times = {'whole_measured_cli': round(wall*1e9), 'context': st['gkr']['cold_ns'],
         'gkr/reference_factors':charged['cpu_factors_ns'],'gkr/reference_rounds':charged['cpu_rounds_wall_ns'],
         'gkr/retained_cpu':charged['retained_cpu_ns'], 'gkr/device':charged['device_path_ns'],
         'gkr/compact_routing_upper':compact_ns,
         'gkr/candidate_with_compact_routing_upper':compact_ns + charged['retained_cpu_ns'] + charged['device_path_ns']}
counters = {'whole_cli_peak_rss_bytes':rss,'gkr/steps':len(device),'gkr/fallbacks':0,
            'gkr/domain_handoffs':sum(bool(r['released_bytes']) for r in device.values()),'gkr/compact_shapes':compact_count,
            'gkr/pool_used_high':st['gkr']['pool_used_high'],'gkr/pool_reserved_high':st['gkr']['pool_reserved_high'],
            'gkr/reserved_plus_outside_bound':max(r['pool_reserved_high']+max(0,r['total_bytes']-r['free_bytes']-r['pool_reserved_bytes']) for r in device.values()),
            'gkr/budget_bytes':device[96]['total_bytes']*2//5,'gkr/h2d_bytes':charged['h2d_bytes'],'gkr/d2h_bytes':charged['d2h_bytes'],
            'gkr/child_views':st['child_views'],'gkr/child_addressable_bytes':st['child_addressable_bytes'],
            'sampled_device_used_high_bytes':max(int(line.split(',')[1].strip().split()[0])*2**20 for line in raw['machine/gpu-memory.csv'].decode().splitlines()[1:] if line.strip())}
for index in (96,97):
    for k,v in device[index].items():
        if k.endswith('_ns'):
            times[f'gkr/{index}/{k}']=v
        else:
            counters[f'gkr/{index}/{k}']=v
for stage in ('top','rebuild','batch_prepare','batch_dense'):
    for k,v in st[stage].items():
        (times if k.endswith('_ns') else counters)[stage+'/'+k]=v
for k,v in st['batch_packing'].items():
    (times if k.endswith('_ns') else counters)['batch_packing/'+k]=v
plan = dict(baseline['model_config']['plan'], stages=['compact_lookup_top_and_resident_rebuild','last_child_gkr_and_ordered_promotions','ordinary_batch_runs_and_dense'])
model = dict(workload=result['workload'],profile=result['profile'],plan=plan,affinity=result['affinity'],inputs=result['inputs'],
             job=result['job'],evidence_location=f"lucid-cluster:~/stele-codex/e16-40z-gkr-memory-schedule/public-{result['job']}.tar.gz",
             source_archive_sha256=verified['source_sha256'],evidence_sha256=verified['archive_sha256'],
             public_receipt_sha256={name:digest(contents) for name,contents in raw.items() if name.startswith(('run/','machine/'))},
             baseline=baseline_name,proof_sha256=result['proof_sha256'],public_sha256=result['public_sha256'],
             cli_sha256=result['cli_sha256'],verifier_sha256=result['verifier_sha256'],slurm_elapsed=verified['slurm_elapsed'],
             seeded=dict(gkr_statements=1000,gkr_steps=2728,gkr_representations=5456,consumed_final_owners=2000),
             scope='Independent CPU verifier accepts the development-tier CPU-produced proof. Device stages check original transcript scalars. Combined production GPU proof parity remains open.')
ledger={k:v for k,v in baseline.items() if k not in ('kernel_counters','model_config','note','plan_digest','stage_times_ns')}
ledger.update(commit=verified['source'],workload='micro/dev-zk-stories42m-t32-gkr-memory-h100',prover_time_ns=round(wall*1e9),
              plan_digest=digest(json.dumps(plan,separators=(',',':'),sort_keys=True).encode()),kernel_counters=counters,stage_times_ns=times,model_config=model)
ledger['note']='Measured all 385 GKR steps with 21 compact lookup trees. Both the CUDA live and reserved high-water counters are independently reported. Reserved pages plus sampled outside-pool usage stayed within the device budget across GKR steps. A conservative compact routing charge retains every compact-leaf CPU factor-construction interval. The T32 proof runs with all checks, both implementations and local stderr. The whole timing includes the comparisons.'
args.output.write_text(json.dumps(ledger,indent=2,sort_keys=True)+'\n')
print(json.dumps({'gkr':st['gkr'],'compact_routing_upper_ns':compact_ns,'upper_ns':times['gkr/candidate_with_compact_routing_upper'],'physical':{k:v for k,v in counters.items() if k in ('gkr/reserved_plus_outside_bound','gkr/budget_bytes')},
                  'changed_steps':{i:{k:device[i][k] for k in ('construction_bytes','first_fold_bytes','released_bytes','pool_used_high','pool_reserved_high')} for i in (96,97)}},indent=2))
