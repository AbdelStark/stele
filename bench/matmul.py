"""RFC-0007 A2 §6 / RFC-0018 §1: complete conditional matmul resource ledger."""
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('lookup_bench_helpers', ROOT/'bench/lookup.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)
PCS, decode, run = L.PCS, L.decode, L.run
CASES = [(c, d, s) for c in ('scalar', 'single', 'stacked', 'zero') for d in (4, 8) for s in range(3)]
MEMORY_SCOPE = 'actual protocol Vec capacities through closed matmul; stack, allocator, runtime, benchmark bookkeeping and subsequent diagnostic A1 excluded; whole-worker RSS separate'


def keys(v, names):
    assert isinstance(v, dict) and set(v) == set(names.split())


def shape(c, scale):
    assert c in ('scalar', 'single', 'stacked', 'zero') and scale in ('full', 'smoke')
    return dict(scalar=[0, 0, 0, 0], single=[0, 4, 5, 3] if scale == 'full' else [0, 1, 1, 2],
                stacked=[2, 3, 4, 2] if scale == 'full' else [1, 1, 1, 2],
                zero=[2, 2, 4, 3] if scale == 'full' else [1, 1, 1, 2])[c]


def python_command(request):
    return ['uv', 'run', '--python', '3.12', '--locked', '--script',
            str(ROOT/'tests/negative-controls/matmul_corpus.py'), '--verify-native', str(request)]


def timing(v, names):
    keys(v['stages_ns'], names)
    assert all(t > 0 for t in v['stages_ns'].values())
    assert v['remainder_ns'] == v['total_ns']-sum(v['stages_ns'].values()) >= 0


def delta(after, before):
    PCS.hashes(after); PCS.hashes(before)
    out = {k: after[k]-before[k] for k in PCS.HASH_KEYS}
    assert min(out.values()) >= 0
    return out


def pcs_work(p, v, ell, r, rate, d, q, size, certificate=False):
    keys(p, 'proof_bytes frame_bytes weights_bytes path_peak_bytes peak_owned_bytes source_elements row_values responses column_bytes_copied path_bytes_copied')
    keys(v, 'frame_bytes weights_bytes row_bytes encoded_bytes encoder peak_owned_bytes responses column_bytes_authenticated column_bytes_decoded path_bytes_copied encoded_values_read')
    rows, columns, length, w = 1 << ell, 1 << r, 1 << (r+rate), 4*d
    assert p['proof_bytes'] >= size and p['path_peak_bytes'] >= 32*(r+rate)
    assert p['source_elements'] == (rows*columns if certificate else 0)
    assert p['row_values'] == columns and p['responses'] == v['responses'] == v['encoded_values_read'] == q
    assert p['column_bytes_copied'] == v['column_bytes_authenticated'] == v['column_bytes_decoded'] == 4*rows*q
    assert p['path_bytes_copied'] == v['path_bytes_copied'] == 32*(r+rate)*q
    assert p['weights_bytes'] >= rows*w if certificate else p['weights_bytes'] == 0
    assert p['frame_bytes'] == 0 if certificate else p['frame_bytes'] >= 145+w*(rows+columns+1)
    assert p['peak_owned_bytes'] == p['proof_bytes']+max(p['frame_bytes'], p['weights_bytes'], p['path_peak_bytes'])
    assert v['frame_bytes'] == 0 if certificate else v['frame_bytes'] == p['frame_bytes']
    assert v['weights_bytes'] >= w*(rows if certificate else rows+columns)
    assert v['row_bytes'] >= columns*w and v['encoded_bytes'] >= length*w
    e = v['encoder']
    keys(e, 'peak_owned_bytes hash_blocks generated_rows sparse_limb_additions sparse_limb_products initialized_symbols copied_symbols circle_calls circle_transform_additions circle_transform_products twiddle_elements inverse_prefix_elements max_recursive_frames')
    assert all(e[k] == 0 for k in ('hash_blocks', 'generated_rows', 'sparse_limb_additions', 'sparse_limb_products', 'max_recursive_frames'))
    assert e['circle_calls'] == 1 and e['peak_owned_bytes'] >= v['encoded_bytes']
    assert e['copied_symbols'] == columns and e['initialized_symbols'] == length-columns
    assert e['circle_transform_additions'] == columns*r+length*(r+rate)
    assert e['circle_transform_products'] == (columns*r//2+columns if r else 0)+length*(r+rate)//2
    assert e['twiddle_elements'] == columns+length-2 and e['inverse_prefix_elements'] == columns-1
    peak = v['row_bytes']+max(e['peak_owned_bytes'], v['encoded_bytes']) if certificate else max(v['frame_bytes'], v['row_bytes']+e['peak_owned_bytes'], v['encoded_bytes'])
    assert v['peak_owned_bytes'] == v['weights_bytes']+peak


def matmul_work(p, v, h, a, b, c, d, size):
    keys(p, 'retained_rows dense context_bytes prepared_bytes proof_bytes row_weights_bytes dense_bytes captured_point_bytes column_weights_bytes a1 round_scratch_peak_bytes openings fold_peak_bytes opening_peak_bytes peak_owned_bytes')
    keys(v, 'context_bytes prepared_bytes decoded_proof_bytes restored_points_bytes a1 openings reduction_peak_bytes opening_peak_bytes peak_owned_bytes')
    r, s, w = h+b, 1 << (h+b), 4*d
    assert p['proof_bytes'] >= size and len(p['retained_rows']) == len(p['row_weights_bytes']) == 2
    assert len(v['restored_points_bytes']) == 2
    for i, ell in enumerate((a, c)):
        row = p['retained_rows'][i]; keys(row, 'source_visits source_elements retained_bytes')
        assert row['source_visits'] == 1 and row['source_elements'] == (1 << ell)*s and row['retained_bytes'] >= s*w
        assert p['row_weights_bytes'][i] >= (1 << ell)*w and v['restored_points_bytes'][i] >= (ell+r)*w
    dense = p['dense']; keys(dense, 'dense_entries partial_entries round_entries round_scratch_entries rounds')
    assert dense['rounds'] == r and dense['dense_entries'] >= 3*s+r
    assert dense['partial_entries'] >= (4*(1 << h) if r else 0) and dense['round_entries'] == (4 if r else 0)
    assert dense['round_scratch_entries'] == dense['partial_entries']+dense['round_entries']
    assert p['dense_bytes'] >= dense['dense_entries']*w+3*24
    assert p['captured_point_bytes'] >= r*w and p['column_weights_bytes'] >= s*w
    for work in (p, v):
        assert work['context_bytes'] >= 304+w*(h+a+c+1)+8 and work['prepared_bytes'] > 0
        assert len(work['openings']) == len(work['opening_peak_bytes']) == 2
    ap, av = p['a1'], v['a1']
    keys(ap, 'round_headers_bytes instance_bytes final_values_bytes final_payload_bytes proof_bytes peak_owned_bytes')
    keys(av, 'instance_bytes round_payload_bytes final_payload_bytes point_bytes claims_bytes peak_owned_bytes')
    assert ap['round_headers_bytes'] >= 24*r and ap['final_values_bytes'] >= 3*w
    assert ap['instance_bytes'] == av['instance_bytes'] >= 60+2*w
    assert ap['final_payload_bytes'] == av['final_payload_bytes'] >= 12+3*w
    assert ap['proof_bytes'] >= ap['round_headers_bytes']+(4*r+3)*w
    assert p['round_scratch_peak_bytes'] >= ap['round_headers_bytes']+dense['round_scratch_entries']*w if r else p['round_scratch_peak_bytes'] == 0
    assert ap['peak_owned_bytes'] >= max(ap['round_headers_bytes']+ap['instance_bytes'], ap['proof_bytes']+ap['final_payload_bytes'])
    assert av['round_payload_bytes'] == (12+4*w if r else 0)
    assert av['point_bytes'] >= r*w and av['claims_bytes'] >= 3*(w+8)
    assert av['peak_owned_bytes'] == av['point_bytes']+av['claims_bytes']+max(av[k] for k in ('instance_bytes', 'round_payload_bytes', 'final_payload_bytes'))
    assert v['decoded_proof_bytes'] >= 24*r+(4*r+3)*w
    base = p['context_bytes']+p['proof_bytes']+sum(p['row_weights_bytes'])+sum(row['retained_bytes'] for row in p['retained_rows'])
    assert p['fold_peak_bytes'] == base+p['prepared_bytes']+p['dense_bytes']+max(ap['peak_owned_bytes'], p['round_scratch_peak_bytes'])
    assert p['opening_peak_bytes'] == [base+p['captured_point_bytes']+p['column_weights_bytes']+o['peak_owned_bytes'] for o in p['openings']]
    base = v['context_bytes']+v['prepared_bytes']+v['decoded_proof_bytes']+sum(v['restored_points_bytes'])
    assert v['reduction_peak_bytes'] == base+av['peak_owned_bytes']
    assert v['opening_peak_bytes'] == [base+av['point_bytes']+av['claims_bytes']+o['peak_owned_bytes'] for o in v['openings']]
    assert p['peak_owned_bytes'] == max(p['fold_peak_bytes'], *p['opening_peak_bytes'])
    assert v['peak_owned_bytes'] == max(v['reduction_peak_bytes'], *v['opening_peak_bytes'])


def receipt(n, py, raw, scenario, d, scale='full'):
    PCS.integers(n); PCS.integers(py)
    keys(n, 'scenario scale field_degree request verification producer_usage producer_continuation diagnostic_probe_usage originals work memory stages_ns total_ns remainder_ns')
    keys(py, 'verification stages_ns total_ns remainder_ns request_sha256 sources runtime diagnostic_probe_usage')
    keys(py['runtime'], 'version executable implementation')
    runtime = py['runtime']
    assert all(isinstance(v, str) and v.strip() for v in runtime.values())
    assert runtime['version'].startswith('3.12.') and runtime['implementation'] == 'cpython'
    assert Path(runtime['executable']).is_absolute()
    assert (n['scenario'], n['field_degree'], n['scale']) == (scenario, d, scale) and d in (4, 8)
    q = n['request']; assert q == decode(raw)
    keys(q, 'degree dims ids point value public_hex originals proof_hex following_hex')
    assert q['degree'] == d and q['dims'] == shape(scenario, scale) and q['ids'] == [101, 102, 103, 104, 105]
    assert q['public_hex'] == b'stele complete matmul measurement v1'.hex()
    h, a, b, c = q['dims']; r, s, w = h+b, 1 << (h+b), 4*d
    assert [len(g) for g in q['point']] == [h, a, c]
    for i, field in enumerate(sum(q['point'], [])):
        assert field == [2+i]+[0]*(d-1)
    assert len(q['value']) == d and all(x < 2147483647 for x in q['value'])
    assert py['request_sha256'] == hashlib.sha256(raw).hexdigest()
    assert set(py['sources']) == {'merkle-oracle/field_wire.py', 'stacked-gkr/stage.py', 'sumcheck/check_sumcheck.py'}
    assert all(hashlib.sha256((ROOT/'research'/p).read_bytes()).hexdigest() == digest for p, digest in py['sources'].items())
    assert py['verification'] == n['verification']
    v = n['verification']; keys(v, 'phase decision imports usage record restored_points consumed_claims continuation')
    assert (v['phase'], v['decision']) == ('outer', 'accept') and len(v['imports']) == 2
    assert len(v['restored_points']) == len(v['consumed_claims']) == 2
    keys(v['record'], 'sc openings'); assert v['record']['sc'] == L.sc(105, r, d)
    assert len(v['record']['openings']) == len(n['originals']) == len(q['originals']) == 2
    keys(n['work'], 'prover verifier'); pwork, vwork = n['work']['prover'], n['work']['verifier']
    wire = PCS.hex_bytes(q['proof_hex'], len(q['proof_hex'])//2); offset, local, queries = 1+w*(4*r+3), 0, 0
    assert wire[:1] == b'\x01'
    memory = n['memory']; keys(memory, 'scope caller_bytes logical_input_bytes output_point_bytes registration_retained_bytes phase_peak_bytes peak_owned_bytes stack_type_bytes')
    assert memory['scope'] == MEMORY_SCOPE and memory['output_point_bytes'] >= (h+a+c)*w
    assert memory['caller_bytes'] == memory['output_point_bytes']+sum(o['message_capacity_bytes'] for o in n['originals'])
    assert len(memory['logical_input_bytes']) == 2
    assert all(cap >= o['message_bytes'] for cap, o in zip(memory['logical_input_bytes'], n['originals']))
    live = memory['caller_bytes']; peaks = {'fixture_layout': live+sum(memory['logical_input_bytes'])}
    for i, ell in enumerate((a, c)):
        info, original, opening = q['originals'][i], n['originals'][i], v['record']['openings'][i]
        keys(info, 'id ell m blowup root_hex source_hex certificate_hex')
        assert (info['id'], info['ell'], info['m'], info['blowup']) == (101+i, ell, r, 1+i)
        keys(opening, 'id queries kind certificate'); cert = opening['certificate']
        keys(cert, 'id source ell degree kind length distance radius certificate_queries opening_queries')
        assert cert['source'] == info['source_hex'] and bytes.fromhex(cert['source'])[73:].hex() == info['root_hex']
        qc, qo, length = L.certificate(dict(id=101+i, context=cert['source'], certificate_id=cert['id'], **{k: val for k, val in cert.items() if k not in ('id', 'source')}), 101+i, ell, r, 1+i, d)
        assert (opening['id'], opening['queries'], opening['kind']) == (101+i, qo, 'Opening')
        assert len(PCS.hex_bytes(info['certificate_hex'], length(qc))) == length(qc)
        keys(original, 'message_bytes message_capacity_bytes certificate_capacity_bytes preparation preparation_hashes producer_usage verifier_usage producer_work verifier_work')
        assert original['message_bytes'] == 4*(1 << ell)*s and original['message_capacity_bytes'] >= original['message_bytes']
        assert original['certificate_capacity_bytes'] == original['producer_work']['proof_bytes'] >= length(qc)
        L.preparation(original['preparation'], ell, r, 1+i)
        PCS.hashes(original['preparation_hashes'], 2*(1 << (r+1+i))-1)
        imported = original['verifier_usage']; keys(imported, 'transcript non_transcript')
        assert imported == v['imports'][i]
        L.registration(original['producer_usage'], dict(transcript=imported['transcript'], local=imported['non_transcript']), ell, r, 1+i, d, qc)
        pcs_work(original['producer_work'], original['verifier_work'], ell, r, 1+i, d, qc, length(qc), True)
        pcs_work(pwork['openings'][i], vwork['openings'][i], ell, r, 1+i, d, qo, length(qo))
        assert wire[offset:offset+1] == b'\x01'; offset += length(qo)
        assert len(v['restored_points'][i]) == ell+r and v['restored_points'][i][:ell] == q['point'][1+i]
        L.claims([v['consumed_claims'][i]], [101+i], d)
        prep = original['preparation']; peaks[f'prepare/{i}'] = live+prep['peak_owned_bytes']
        live += prep['encoded_columns_bytes']+prep['merkle_nodes_bytes']
        peaks[f'certificate_prove/{i}'] = live+original['producer_work']['peak_owned_bytes']
        live += original['certificate_capacity_bytes']
        peaks[f'certificate_verify/{i}'] = live+original['verifier_work']['peak_owned_bytes']
        local += qo*(1+r+1+i); queries += qo
    assert offset == len(wire); PCS.hex_bytes(q['following_hex'], 3*w)
    matmul_work(pwork, vwork, h, a, b, c, d, len(wire))
    assert memory['registration_retained_bytes'] == live
    peaks |= {'prove': live+pwork['peak_owned_bytes'], 'verify': live+pwork['proof_bytes']+vwork['peak_owned_bytes']}
    assert memory['phase_peak_bytes'] == peaks and memory['peak_owned_bytes'] == max(peaks.values())
    keys(memory['stack_type_bytes'], 'prepared_source certificate record transcript producer_work verifier_work')
    assert all(x > 0 for x in memory['stack_type_bytes'].values())
    keys(n['producer_usage'], 'transcript non_transcript'); keys(v['usage'], 'transcript non_transcript')
    assert n['producer_usage']['transcript'] == v['usage']['transcript']; u = v['usage']['transcript']; L.transcript(u, d)
    PCS.hashes(n['producer_usage']['non_transcript'], 0); PCS.hashes(v['usage']['non_transcript'], local)
    assert queries <= u['column_attempts'] <= 64*queries and u['xof_requests'] == r+u['column_attempts']
    assert u['hash_evaluations'] == 12+r+u['xof_requests']
    continuation = v['continuation']; keys(continuation, 'decision sc point usage probe')
    assert continuation['decision'] == 'accept' and continuation['sc'] == dict(id=901, m=1, degree=1, field_degree=d, numerator=1)
    assert len(continuation['point']) == 1; L.field(continuation['point'][0], d); L.field(continuation['probe'], d)
    assert n['producer_continuation'] == {k: continuation[k] for k in ('usage', 'probe')}
    keys(n['diagnostic_probe_usage'], 'producer consumer')
    assert n['diagnostic_probe_usage']['producer'] == n['diagnostic_probe_usage']['consumer'] == py['diagnostic_probe_usage']
    follow = delta(continuation['usage'], u); probe = delta(py['diagnostic_probe_usage'], continuation['usage'])
    assert follow['hash_evaluations'] == follow['state_updates'] == 4 and follow['xof_requests'] == 1
    assert probe['hash_evaluations'] == probe['state_updates'] == probe['xof_requests'] == 1
    for step in (follow, probe):
        assert step['xof_bytes'] == 256 and d <= step['candidate_words'] <= 64 and step['column_attempts'] == 0
    timing(n, 'fixture expected_claim physical_layout prepare/0 prepare/1 certificate_prove/0 certificate_prove/1 certificate_verify/0 certificate_verify/1 transcripts prove verify following_a1 observations cleanup')
    timing(py, 'decode certificate_import_x certificate_import_w closed_relation continuation')


def artifact(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def compact(n, py, raw):
    # The external request retains complete actual wires. The imported ledger
    # carries each exact section's bytes/hash and all observed records and work.
    q = n['request']; r = q['dims'][0]+q['dims'][2]; width = 4*q['degree']
    wire = bytes.fromhex(q['proof_hex']); offset = 1+width*(4*r+3)
    sections = [dict(name='version_a1', **artifact(wire[:offset]))]
    for i in range(2):
        # Capacity is not a wire length; derive length from the actual certificate.
        c = n['verification']['record']['openings'][i]['certificate']
        size = 1+width*(1 << r)+c['opening_queries']*(4*(1 << c['ell'])+32*(r+1+i))
        sections.append(dict(name='X' if i == 0 else 'W', **artifact(wire[offset:offset+size]), row=artifact(wire[offset+1:offset+1+width*(1 << r)])))
        offset += size
    request = {k: v for k, v in q.items() if k not in ('originals', 'proof_hex', 'following_hex')}
    request['originals'] = [{k: v for k, v in o.items() if k != 'certificate_hex'} | {'certificate': artifact(bytes.fromhex(o['certificate_hex']))} for o in q['originals']]
    return {k: v for k, v in n.items() if k != 'request'} | dict(public=request, request=artifact(raw),
        proof=artifact(wire), sections=sections, following=artifact(bytes.fromhex(q['following_hex'])), python=py)


def check_cases(records):
    assert [(r['scenario'], r['field_degree'], r['sample']) for r in records] == CASES


def identity(v):
    volatile = {'stages_ns', 'total_ns', 'remainder_ns', 'sample', 'processes', 'artifacts'}
    return {k: identity(x) if isinstance(x, dict) else x for k, x in v.items() if k not in volatile}


def assemble(metadata, records):
    transcripts = [h for r in records for h in [r['producer_usage']['transcript'], r['verification']['usage']['transcript'], r['python']['verification']['usage']['transcript']]
        +[u for o in r['originals'] for u in (o['producer_usage'], o['verifier_usage']['transcript'])]+[o['transcript'] for o in r['python']['verification']['imports']]]
    stages = {f'{i}/{lang}/{s}': t for i, r in enumerate(records) for lang, v in [('native', r), ('python', r['python'])] for s, t in (v['stages_ns']|{'remainder': v['remainder_ns']}).items()}
    return dict(schema_version=1, kind='micro', workload='micro/conditional-matmul', commit=metadata['commit'],
        toolchain=metadata['toolchain'], device=metadata['device'], driver='not-applicable', model_config=dict(**metadata, samples=records),
        plan_digest=hashlib.sha256(json.dumps(metadata['plan'], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        profile='standard', bindings_all_on=True, batch_size=1, prompt_tokens=0, generated_tokens=0,
        prover_time_ns=sum(stages.values()), witness_recompute_ns=0, stage_times_ns=stages,
        kernel_counters=dict(disjoint_protocol_transcript_hashes=sum(u['hash_evaluations'] for u in transcripts),
            preparation_hashes=sum(o['preparation_hashes']['hash_evaluations'] for r in records for o in r['originals']),
            registration_local_hashes=sum(o['verifier_usage']['non_transcript']['hash_evaluations'] for r in records for o in r['originals'])+sum(o['non_transcript']['hash_evaluations'] for r in records for o in r['python']['verification']['imports']),
            closed_verifier_local_hashes=sum(r['verification']['usage']['non_transcript']['hash_evaluations']+r['python']['verification']['usage']['non_transcript']['hash_evaluations'] for r in records),
            diagnostic_following_and_probe_hashes=sum(delta(after, before)['hash_evaluations'] for r in records for after, before in
                [(r['diagnostic_probe_usage']['producer'], r['producer_usage']['transcript']), (r['diagnostic_probe_usage']['consumer'], r['verification']['usage']['transcript']), (r['python']['diagnostic_probe_usage'], r['python']['verification']['usage']['transcript'])]),
            original_proof_elements=sum(o['source_elements'] for r in records for o in r['work']['prover']['retained_rows'])),
        proof_size_bytes=0, verifier_time_ns=dict(rust=0, python=0), controls=dict(total=0, passed=0, failed=0),
        note='Complete conditional matmul with actual original registration, native producer, native and independent Python closed consumers; all bindings on. Actual component wires/timings/capacities and process RSS in samples; root inference fields zero. Witness recompute is absent for supplied field matrices; fixture claim/layout time is explicit. Standard is a schema tag, with no CQIS/inference/privacy/profile admission, fitted constant or speedup claim.')


def main():
    if sys.version_info[:2] != (3, 12) or sys.flags.optimize:
        raise SystemExit('requires Python 3.12 with assertions enabled')
    if len(sys.argv) != 2 or (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise SystemExit('usage: uv run --no-project --python 3.12 python bench/matmul.py <new-external-ledger.json>')
    output = Path(sys.argv[1]).absolute(); raw = output.with_suffix('.samples')
    if output.exists() or raw.exists() or ROOT in output.resolve().parents or run('git', 'status', '--porcelain'):
        raise SystemExit('requires clean committed source and new external output/sample paths')
    commit, tree = run('git', 'rev-parse', 'HEAD'), run('git', 'rev-parse', 'HEAD^{tree}')
    plan = dict(cases=CASES, shapes={c: shape(c, 'full') for c in ('scalar', 'single', 'stacked', 'zero')}, rates=[1, 2], workers=1,
        fixture='logical X=(index mod31)-15, W=(index mod29)-14 or all-zero; physical X(i,l,k), W(j,l,k); public point consecutive base-field values from2; IDs101..105; fixed prefix across repetitions',
        limits=dict(descriptor_bytes=16_000_000, proof_bytes=16_000_000, prepared_entries=65_536, partial_entries=65_536, axis_entries=65_536, retained_row_entries=65_536),
        sampling='three repetitions per cell in fixed order; fresh native and locked Python workers; no warmup, retries or discarded samples; shared host, original workers preserved',
        timing='native fixture through protocol cleanup, disjoint stages and remainder; Python request decode through independent imports/closed verifier/continuation/cleanup; configure/startup/serialization in external process wall and RSS only',
        capacities=MEMORY_SCOPE, stack='reported type sizes are not a compiler stack peak; fixed arrays/headers on stack excluded from Vec payloads',
        row_identity='actual retained_rows visits/elements; opening source_elements zero; actual OpeningRow sections retained with byte lengths and SHA256; immutable path in frozen matmul_producer.rs and pcs/opening.rs, not a boolean receipt',
        usage='each distinct native/Python registration and outer transcript once; cumulative continuation and probe deltas separately; ordinary local hashes disjoint; receipt SHA256 outside protocol',
        scope='conditional CPU field relation only; no integer, virtual-source, configured-plan, packing, bucketed weight phase, privacy, Q12, W8, profile or comparative performance credit')
    raw.mkdir(parents=True)
    sources = {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in run('git', 'ls-files').splitlines()
               if p.startswith(('crates/', 'research/', 'tests/negative-controls/', 'bench/', 'scripts/')) and (ROOT/p).is_file()}
    metadata = dict(commit=commit, tree=tree, plan=plan, source_sha256=sources, toolchain=run('rustc', '-Vv'), cargo=run('cargo', '--version'),
        artifact_directory=str(raw.resolve()), os=platform.platform(), python=sys.version, uv=run('uv', '--version'), device=platform.machine()+' '+run('sysctl', '-n', 'machdep.cpu.brand_string'))
    def save(path, data):
        with path.open('xb') as stream: stream.write(data)
    save(raw/'provenance-before-build.json', (json.dumps(metadata, indent=2)+'\n').encode())
    with (raw/'build.log').open('x') as stream:
        subprocess.run(['cargo', 'build', '-p', 'stele-negative-controls', '--example', 'matmul_bench', '--release', '--locked', '--offline'], cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=True)
    binary = ROOT/'target/release/examples/matmul_bench'; metadata['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    save(raw/'provenance.json', (json.dumps(metadata, indent=2)+'\n').encode())
    def unchanged():
        assert run('git', 'rev-parse', 'HEAD') == commit and run('git', 'rev-parse', 'HEAD^{tree}') == tree
        assert not run('git', 'status', '--porcelain') and hashlib.sha256(binary.read_bytes()).hexdigest() == metadata['binary_sha256']
    records = []
    for i, (scenario, d, sample) in enumerate(CASES):
        unchanged(); paths = {}; processes = {}
        def worker(name, command):
            stats = raw/f'{i:02d}.{name}.time'; start = perf_counter_ns()
            result = subprocess.run(['/usr/bin/time', '-l', '-o', str(stats), *command], cwd=ROOT, capture_output=True)
            wall = perf_counter_ns()-start
            for suffix, value in [('stdout', result.stdout), ('stderr', result.stderr), ('exit', f'{result.returncode}\n'.encode())]:
                path = raw/f'{i:02d}.{name}.{suffix}'; save(path, value); paths[path.name] = artifact(value)
            report = stats.read_bytes(); paths[stats.name] = artifact(report)
            result.check_returncode()
            peaks = [int(line.split()[0]) for line in report.decode().splitlines() if 'maximum resident set size' in line]
            assert len(peaks) == 1 and peaks[0] > 0 and wall > 0
            processes[name] = dict(wall_ns=wall, peak_rss_bytes=peaks[0])
            return decode(result.stdout)
        n = worker('native', [str(binary), scenario, str(d), 'full'])
        request = (json.dumps(n['request'], sort_keys=True, separators=(',', ':'))+'\n').encode()
        path = raw/f'{i:02d}.request.json'; save(path, request); paths[path.name] = artifact(request)
        py = worker('python', python_command(path)); receipt(n, py, request, scenario, d); unchanged()
        records.append(compact(n, py, request)|dict(sample=sample, processes=processes, artifacts=paths))
        print(f'Validated {scenario}/{d}/{sample}', flush=True)
    check_cases(records); unchanged()
    for i in range(0, len(records), 3): assert identity(records[i]) == identity(records[i+1]) == identity(records[i+2])
    encoded = (json.dumps(assemble(metadata, records), separators=(',', ':'))+'\n').encode()
    assert len(encoded) <= 1 << 20
    save(output, encoded)
    subprocess.run(['cargo', 'run', '-p', 'stele-bench', '--locked', '--offline', '--', 'ledger', 'validate', str(output)], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
