"""RFC-0006 A4 §6: complete public/certified native stacked resource receipts."""
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('pcs_bench_helpers', ROOT/'bench/field_pcs.py')
PCS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PCS)
decode, run = PCS.decode, PCS.run
CELLS = [(mode, order, degree) for mode in ('public','certified')
         for degree in (4,8) for order in ('first','last')]
CASES = [(*cell,sample) for cell in CELLS for sample in range(3)]


def sized(value, length):
    assert set(value)=={'bytes','digest'} and value['bytes']==length
    PCS.hex_bytes(value['digest'],32)


def field(value, length):
    raw=PCS.hex_bytes(value,length)
    assert all(int.from_bytes(raw[i:i+4],'little')<2147483647 for i in range(0,length,4))


def receipt(v,mode,order,d,scale='full'):
    PCS.integers(v)
    assert set(v)=={'mode','order','field_degree','scale','axes','claim','coefficient','selector','inputs',
        'backing_capacity_bytes','framing','sources','record','a1','dense','producer_usage','consumer_usage',
        'continuation','stages_ns','total_ns','remainder_ns'}
    assert (v['mode'],v['order'],v['field_degree'],v['scale'])==(mode,order,d,scale)
    assert mode in ('public','certified') and order in ('first','last') and d in (4,8) and scale in ('full','smoke')
    bits,splits=([4,5,5],[4,7,10]) if scale=='full' else ([1,1,1],[0,1,3])
    ell,m,k=bits[0],sum(bits),4*d
    n,c=1<<m,1<<(m-ell)
    assert v['axes']==[dict(bits=b,real=1<<b) for b in bits]
    field(v['claim'],k);field(v['selector'],ell*k)
    assert set(v['continuation'])=={'producer','consumer'}
    field(v['continuation']['producer'],k);assert v['continuation']['producer']==v['continuation']['consumer']
    sized(v['coefficient'],4*c)
    assert len(v['inputs'])==3
    for i,x in enumerate(v['inputs']):
        assert set(x)=={'id','canonical','capacity_bytes'} and x['id']==41+i
        size=n*(4 if mode=='certified' else k)
        sized(x['canonical'],size);assert x['capacity_bytes']>=size
    backing=v['backing_capacity_bytes']
    assert set(backing)=={'selector','coefficient','term_factors'}
    assert backing['selector']>=ell*k and backing['coefficient']>=4*c and backing['term_factors']>=16
    assert set(v['framing'])=={'stack','sources','instance'}
    sized(v['framing']['stack'],129+(3+ell)*k+4*c)
    sized(v['framing']['sources'],425 if mode=='certified' else 14+3*(8+n*k))
    sized(v['framing']['instance'],81+3*k)
    a=v['a1'];assert set(a)=={'rounds','finals','messages','field_capacity_bytes','round_headers_capacity_bytes'}
    assert (a['rounds'],a['finals'])==(m,4)
    sized(a['messages'],m*(12+5*k)+12+4*k)
    assert a['field_capacity_bytes']>=(5*m+4)*k and a['round_headers_capacity_bytes']>=m*24
    w=v['dense'];assert set(w)=={'dense_entries','partial_entries','round_entries','round_scratch_entries','rounds'}
    assert w['rounds']==m and w['dense_entries']>=4*n+m
    assert w['partial_entries']>=5*(1<<ell) and w['round_entries']>=5
    assert max(w['partial_entries']+5,w['round_entries']+5*(1<<ell))<=w['round_scratch_entries']<=w['partial_entries']+w['round_entries']
    record=v['record'];assert set(record)=={'sc','openings','claims'}
    assert record['sc']==dict(id=71,m=m,degree=4,field_degree=d,numerator=4*m)
    assert len(v['sources'])==(3 if mode=='certified' else 0)
    stages={'fixture','transcripts','produce','verify','observations'}
    local=queries=0
    if mode=='certified':
        assert len(record['openings'])==3 and record['claims']==[]
        for i,(s,o,r) in enumerate(zip(v['sources'],record['openings'],splits)):
            stages|={f'{stage}/{i}' for stage in ('prepare','certificate_prove','certificate_verify')}
            columns,length,height=1<<(m-r),1<<(m-r+1),m-r+1
            qc,qo=PCS.policy(m-r,1);distance=length if columns==1 else length-columns
            assert set(s)=={'id','context','certificate_id','row_bits','field_degree','kind','parameters','certificate',
                'certificate_capacity_bytes','producer','verifier','preparation_hashes','preparation','point_weight_entries'}
            assert (s['id'],s['row_bits'],s['field_degree'],s['kind'])==(41+i,r,d,'Certificate')
            raw=PCS.hex_bytes(s['context'],105);PCS.hex_bytes(s['certificate_id'],32)
            assert raw[:25]==b'stele/v0.1/field-source'+bytes([1,d])
            assert int.from_bytes(raw[25:33],'little')==41+i and raw[33]==r
            assert raw[53:55]==bytes([m-r,1]) and raw[71:73]==bytes([0,1])
            assert int.from_bytes(raw[55:63],'little')==1<<r and int.from_bytes(raw[63:71],'little')==columns
            assert s['parameters']==dict(length=length,distance=distance,radius=(distance-1)//3,certificate_queries=qc,opening_queries=qo)
            wire=lambda q:1+k*columns+q*(4*(1<<r)+32*height)
            sized(s['certificate'],wire(qc));assert s['certificate_capacity_bytes']>=wire(qc)
            assert s['point_weight_entries']==(1<<r)+columns
            work=s['preparation'];assert set(work)=={'borrowed_message_bytes','encoded_columns_bytes','encoder_peak_bytes','leaf_references_bytes','merkle_nodes_bytes','peak_owned_bytes'}
            assert work['borrowed_message_bytes']==4*n and work['encoded_columns_bytes']>=4*(1<<r)*length
            assert work['encoder_peak_bytes']>=4*length and work['leaf_references_bytes']>=16*length and work['merkle_nodes_bytes']>=32*(2*length-1)
            assert work['peak_owned_bytes']==work['encoded_columns_bytes']+max(work['encoder_peak_bytes'],work['leaf_references_bytes']+work['merkle_nodes_bytes'])
            PCS.hashes(s['preparation_hashes'],2*length-1);PCS.hashes(s['producer'])
            assert set(s['verifier'])=={'transcript','local'};PCS.hashes(s['verifier']['local'],qc*(1+height)+1)
            assert s['producer']==s['verifier']['transcript']
            assert s['producer']['column_attempts']>=qc and s['producer']['xof_requests']==r+s['producer']['column_attempts']
            assert s['producer']['hash_evaluations']==s['producer']['xof_requests']+4
            assert set(o)=={'id','queries','kind','certificate_id','wire','capacity_bytes'}
            assert (o['id'],o['queries'],o['kind'],o['certificate_id'])==(41+i,qo,'Opening',s['certificate_id'])
            sized(o['wire'],wire(qo));assert o['capacity_bytes']>=wire(qo)
            local+=qo*(1+height);queries+=qo
    else:
        assert record['openings']==[] and len(record['claims'])==3
        for i,x in enumerate(record['claims']):
            assert set(x)=={'id','value'} and x['id']==41+i;field(x['value'],k)
    for key,expected in (('producer_usage',0),('consumer_usage',local)):
        assert set(v[key])=={'transcript','local'};PCS.hashes(v[key]['transcript']);PCS.hashes(v[key]['local'],expected)
    u=v['consumer_usage']['transcript'];assert v['producer_usage']['transcript']==u
    assert u['column_attempts']>=queries and u['xof_requests']==m+u['column_attempts']
    assert u['hash_evaluations']==6+2*m+(9 if mode=='certified' else 0)+u['column_attempts']
    for h in [u,*[s['producer'] for s in v['sources']]]:
        assert h['state_updates']+1==h['hash_evaluations'] and h['xof_bytes']==256*h['xof_requests']
        assert h['candidate_words']>=d*h['xof_requests']
    assert set(v['stages_ns'])==stages and all(t>0 for t in v['stages_ns'].values())
    assert v['total_ns']>=sum(v['stages_ns'].values()) and v['remainder_ns']==v['total_ns']-sum(v['stages_ns'].values())


def check_cases(records):
    assert [(r['mode'],r['order'],r['field_degree'],r['sample']) for r in records]==CASES


def identity(v):
    return {k:value for k,value in v.items() if k not in {'stages_ns','total_ns','remainder_ns','sample','peak_rss_bytes','native_time_resource_report'}}


def assemble(metadata,records):
    return dict(schema_version=1,kind='micro',workload='micro/conditional-stacked',commit=metadata['commit'],
        toolchain=metadata['toolchain'],device=metadata['device'],driver='not-applicable',model_config=dict(**metadata,samples=records),
        plan_digest=hashlib.sha256(json.dumps(metadata['plan'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        profile='standard',bindings_all_on=True,batch_size=1,prompt_tokens=0,generated_tokens=0,
        prover_time_ns=sum(r['total_ns'] for r in records),witness_recompute_ns=0,
        stage_times_ns={f'{i}/{s}':t for i,r in enumerate(records) for s,t in (r['stages_ns']|{'remainder':r['remainder_ns']}).items()},
        kernel_counters={'dense_rounds':sum(r['dense']['rounds'] for r in records),
            'preparation_hashes':sum(s['preparation_hashes']['hash_evaluations'] for r in records for s in r['sources']),
            'opening_merkle_hashes':sum(r['consumer_usage']['local']['hash_evaluations'] for r in records)},
        proof_size_bytes=0,verifier_time_ns=dict(rust=0,python=0),controls=dict(total=0,passed=0,failed=0),
        note='Complete conditional stacked public/certified calls and registration; all originals consumed. '
             'All samples retained; inclusive cleanup and whole-worker RSS. Scoped capacities are not a pipeline peak. '
             'Standard is a schema tag; no inference/profile/privacy admission, fit, speedup or weight-pass claim.')


def main():
    if len(sys.argv)!=2 or (platform.system(),platform.machine())!=('Darwin','arm64'):
        raise SystemExit('usage: uv run --no-project --python 3.12 python bench/stacked.py <new-external-ledger.json>')
    output=Path(sys.argv[1]).absolute();raw=output.with_suffix('.samples')
    if output.exists() or raw.exists() or ROOT in output.parents or run('git','status','--porcelain'):
        raise SystemExit('requires clean committed source and new external output/sample paths')
    commit,tree=run('git','rev-parse','HEAD'),run('git','rev-parse','HEAD^{tree}')
    plan=dict(cases=CASES,workers=1,samples_per_cell=3,build='release',
        sampling='fixed order; no warmup, retries, cache flush or discarded samples',
        relation='m14 axes(4,5,5), stage71, originals41/42/43, coefficient99, source119, scalar output17; P=3*f0^3+0*f2; all3 consumed',
        fixture='original M31[s][i]=(37*i+101*s+9) mod p; RopeTables axes[1,2], value[i]=13*i+7; layer selector limb[j]=37*(17+bit)+17*j+9',
        pcs='each original actually prepared/registered; splits(4,10),(7,7),(10,4), blowup1; original certificate lifetime retained',
        limits=dict(descriptor_bytes=1<<28,proof_bytes=1<<28,prepared_entries=1<<24,partial_entries=1<<20,axis_entries=1<<20),
        timing='inclusive fixture/claim, registration, closed producer/consumer, observations/continuation and protocol cleanup; excludes build, launch, argument parsing, final JSON serialization; no replay',
        memory='fresh-worker whole-pipeline RSS including observation/serialization/runtime/allocator retention; caller originals, source trees, certificates and complete proof retained through consumer; Dense tables drop before openings',
        capacities='actual Dense selected field capacities, source PreparationWork and direct caller/proof payload capacities only; not a complete owned peak; structural point_weight_entries are not capacities',
        framing='expected canonical frames reconstructed and charged during observation, not captured transcript bytes; proof messages/certificate/opening sizes separate',
        usage='actual cumulative stage snapshots; independent registration transcripts; only disjoint local hashes summed; no failed-producer/sampler usage or adversarial cap claim',
        scope='bounded CPU micro, one RopeTables relation, both fields/orders/modes; shared host with original research workers preserved; no scalar/padding/all-kind scaling or comparative speed claim')
    raw.mkdir(parents=True)
    metadata=dict(commit=commit,tree=tree,plan=plan,toolchain=run('rustc','-Vv'),cargo=run('cargo','--version'),
        os=platform.platform(),python=sys.version,device=platform.machine()+' '+run('sysctl','-n','machdep.cpu.brand_string'))
    (raw/'provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    with (raw/'build.log').open('x') as stream:
        subprocess.run(['cargo','build','-p','stele-negative-controls','--example','stacked_bench','--release','--locked','--offline'],cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,check=True)
    binary=ROOT/'target/release/examples/stacked_bench';metadata['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
    (raw/'provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    def unchanged():
        assert run('git','rev-parse','HEAD')==commit and run('git','rev-parse','HEAD^{tree}')==tree
        assert not run('git','status','--porcelain') and hashlib.sha256(binary.read_bytes()).hexdigest()==metadata['binary_sha256']
    records=[]
    for i,(mode,order,d,sample) in enumerate(CASES):
        unchanged();stats=raw/f'{i:02d}.time.txt'
        result=subprocess.run(['/usr/bin/time','-l','-o',str(stats),str(binary),mode,order,str(d),'full'],cwd=ROOT,text=True,capture_output=True)
        for suffix,value in [('stdout',result.stdout),('stderr',result.stderr),('exit',str(result.returncode)+'\n')]:
            (raw/f'{i:02d}.{suffix}').write_text(value)
        result.check_returncode();unchanged();v=decode(result.stdout);receipt(v,mode,order,d)
        report=stats.read_text();peaks=[int(line.split()[0]) for line in report.splitlines() if 'maximum resident set size' in line]
        assert len(peaks)==1 and peaks[0]>0
        records.append(dict(**v,sample=sample,peak_rss_bytes=peaks[0],native_time_resource_report=report))
        print(f'Validated {mode}/{order}/{d}/{sample}',flush=True)
    check_cases(records);unchanged()
    for i in range(0,len(records),3):assert identity(records[i])==identity(records[i+1])==identity(records[i+2])
    with output.open('x') as stream:json.dump(assemble(metadata,records),stream,indent=2);stream.write('\n')
    subprocess.run(['cargo','run','-p','stele-bench','--locked','--offline','--','ledger','validate',str(output)],cwd=ROOT,check=True)


if __name__=='__main__':main()
