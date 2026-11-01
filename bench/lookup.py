"""RFC-0008 A5 §6 / RFC-0018 §1: complete conditional lookup resource receipts."""
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
CASES = [(c, d, s) for c in ('scalar', 'grouped', 'signed', 'zero') for d in (4, 8) for s in range(3)]
MEMORY_SCOPE = 'actual named producer boundary capacities; excludes metadata and internal scratch; whole-worker RSS separate'


def shape(scenario, scale):
    assert scenario in ('scalar', 'grouped', 'signed', 'zero') and scale in ('full', 'smoke')
    full = scale == 'full'
    m, b, t, n, c, ells, mu = {
        'scalar': (0, 0, 256, 256, 1, [0], [(4, 1)]),
        'grouped': (12 if full else 2, 0, 3, 4, 2, [4, 8] if full else [0, 2], [(1, 1), (0, 2)]),
        'signed': (12 if full else 2, 12 if full else 2, 129, 256, 2, [4, 8] if full else [0, 2], [(4, 1), (5, 2)]),
        'zero': (8 if full else 3, 4 if full else 1, 3, 4, 2, [2, 6] if full else [1, 2], [(2, 2)]),
    }[scenario]
    return dict(m=m, b=b, table_rows=t, padded_rows=n, columns=c, repetitions=len(mu), original_ells=ells,
                mu_layouts=[dict(id=81+j, ell=ell, blowup=blowup) for j, (ell, blowup) in enumerate(mu)])


def sized(v, count):
    assert set(v) == {'bytes', 'digest'} and v['bytes'] == count
    PCS.hex_bytes(v['digest'], 32)


def field(v, d):
    raw = PCS.hex_bytes(v, 4*d)
    assert all(int.from_bytes(raw[i:i+4], 'little') < 2147483647 for i in range(0, 4*d, 4))


def transcript(v, d):
    PCS.hashes(v)
    assert v['hash_evaluations'] == v['state_updates']+1
    assert v['xof_bytes'] == 256*v['xof_requests'] and d*v['xof_requests'] <= v['candidate_words'] <= 64*v['xof_requests']


def certificate(v, ident, ell, m, blowup, d):
    assert set(v) == {'id', 'context', 'certificate_id', 'ell', 'degree', 'kind', 'length',
                      'distance', 'radius', 'certificate_queries', 'opening_queries'}
    assert (v['id'], v['ell'], v['degree'], v['kind']) == (ident, ell, d, 'Certificate')
    raw = PCS.hex_bytes(v['context'], 105)
    assert raw[:25] == b'stele/v0.1/field-source'+bytes([1, d])
    assert int.from_bytes(raw[25:33], 'little') == ident and raw[33] == ell
    assert raw[34:53] == b'stele/circle-m31/v1'
    assert raw[53:55] == bytes([m, blowup]) and raw[71:73] == bytes([0, 1])
    rows, columns, length = 1 << ell, 1 << m, 1 << (m+blowup)
    assert int.from_bytes(raw[55:63], 'little') == rows and int.from_bytes(raw[63:71], 'little') == columns
    distance = length if columns == 1 else length-columns
    qc, qo = PCS.policy(m, blowup)
    assert (v['length'], v['distance'], v['radius'], v['certificate_queries'], v['opening_queries']) == (length, distance, (distance-1)//3, qc, qo)
    PCS.hex_bytes(v['certificate_id'], 32)
    return qc, qo, lambda q: 1+4*d*columns+q*(4*rows+32*(m+blowup))


def preparation(w, ell, m, blowup):
    assert isinstance(w, dict) and set(w) == {'borrowed_message_bytes', 'encoded_columns_bytes', 'encoder_peak_bytes',
                      'leaf_references_bytes', 'merkle_nodes_bytes', 'peak_owned_bytes'}
    rows, columns, length = 1 << ell, 1 << m, 1 << (m+blowup)
    assert w['borrowed_message_bytes'] == 4*rows*columns
    assert w['encoded_columns_bytes'] >= 4*rows*length and w['encoder_peak_bytes'] >= 4*length
    assert w['leaf_references_bytes'] >= 16*length and w['merkle_nodes_bytes'] >= 32*(2*length-1)
    assert w['peak_owned_bytes'] == w['encoded_columns_bytes']+max(w['encoder_peak_bytes'], w['leaf_references_bytes']+w['merkle_nodes_bytes'])


def registration(producer, verifier, ell, m, blowup, d, qc):
    transcript(producer, d)
    assert set(verifier) == {'transcript', 'local'} and verifier['transcript'] == producer
    PCS.hashes(verifier['local'], qc*(1+m+blowup)+1)
    assert qc <= producer['column_attempts'] <= 64*qc
    assert producer['xof_requests'] == ell+producer['column_attempts']
    assert producer['hash_evaluations'] == 4+producer['xof_requests']


def sc(ident, m, d):
    return dict(id=ident, m=m, degree=3, field_degree=d, numerator=3*m)


def claims(v, ids, d):
    assert len(v) == len(ids)
    for claim, ident in zip(v, ids):
        assert len(claim) == 2 and claim[0] == ident
        field(claim[1], d)


def tree(v, ident, m, d):
    assert set(v) == {'point', 'claims', 'accounting'} and len(v['point']) == m
    for x in v['point']:
        field(x, d)
    claims(v['claims'], [2*ident, 2*ident+1], d)
    assert v['accounting'] == dict(tree_id=ident, field_degree=d, gamma=m, fold=m, layers=[sc(j, j, d) for j in range(m)])


def opening(v, ident, cert):
    assert v == dict(id=ident, queries=cert['opening_queries'], kind='Opening', certificate_id=cert['certificate_id'])


def fraction(w, m, c, d, selected=False):
    assert set(w) == {'levels_bytes', 'dense_bytes', 'proof_bytes', 'point_bytes', 'peak_observed_bytes'}
    width = 4*d
    if selected:
        assert w['levels_bytes'] == 0 and w['dense_bytes'] >= (c+2)*(1 << m)*width
        assert w['proof_bytes'] >= (4*m+c+2)*width and w['point_bytes'] >= m*width
    else:
        assert w['levels_bytes'] >= 2*((1 << (m+1))-1)*width
        assert w['dense_bytes'] >= (5*(1 << (m-1))*width if m else 0)
        assert w['proof_bytes'] >= (2*m*m+3*m)*width and w['point_bytes'] >= max(0, 2*m-1)*width
    assert w['peak_observed_bytes'] >= max(w[k] for k in ('levels_bytes', 'dense_bytes', 'proof_bytes', 'point_bytes'))


def receipt(v, scenario, d, scale='full'):
    PCS.integers(v)
    assert set(v) == {'scenario', 'scale', 'field_degree', 'shape', 'originals', 'multiplicities', 'framing',
                      'proof', 'record', 'producer_usage', 'consumer_usage', 'work', 'memory_scope', 'admission',
                      'continuation', 'diagnostics', 'stages_ns', 'total_ns', 'remainder_ns'}
    assert (v['scenario'], v['field_degree'], v['scale']) == (scenario, d, scale) and d in (4, 8)
    s = shape(scenario, scale)
    assert v['shape'] == s and v['memory_scope'] == MEMORY_SCOPE
    m, b, t, n, c, r = (s[k] for k in ('m', 'b', 'table_rows', 'padded_rows', 'columns', 'repetitions'))
    k, h, width, positions = n.bit_length()-1, m-b, 4*d, 1 << m
    assert len(v['originals']) == c and len(v['multiplicities']) == r
    stages = {'fixture', 'descriptor', 'transcripts', 'produce_including_mu_preparation_and_registration',
              'import_multiplicities', 'verify', 'observations'}
    original_sizes, original_local, original_queries = [], 0, 0
    for i, (o, ell) in enumerate(zip(v['originals'], s['original_ells'])):
        assert set(o) == {'certificate', 'wire', 'capacity_bytes', 'input', 'input_capacity_bytes', 'preparation', 'preparation_hashes', 'producer', 'verifier'}
        qc, qo, wire = certificate(o['certificate'], 41+i, ell, m-ell, 1, d)
        sized(o['wire'], wire(qc)); sized(o['input'], 4*positions)
        assert o['capacity_bytes'] >= wire(qc) and o['input_capacity_bytes'] >= 4*positions
        preparation(o['preparation'], ell, m-ell, 1)
        PCS.hashes(o['preparation_hashes'], 2*(1 << (m-ell+1))-1)
        registration(o['producer'], o['verifier'], ell, m-ell, 1, d, qc)
        original_sizes.append(wire(qo)); original_local += qo*(2+m-ell); original_queries += qo
        stages |= {f'{stage}/{i}' for stage in ('prepare', 'certificate_prove', 'certificate_verify')}
    assert set(v['producer_usage']) == {'transcript', 'local', 'registrations'}
    regs = v['producer_usage']['registrations']
    assert len(regs) == 2 and regs[r:] == [None]*(2-r)
    assert set(v['consumer_usage']) == {'transcript', 'local'}
    producer_local, consumer_local, queries, pieces, mu_sizes = 1, 1+r+r*original_local, r*original_queries, [], []
    sections = [('header', 2)]
    w = v['work']
    keys = {'proof_bytes', 'units_bytes', 'index_bytes', 'group_weights_bytes', 'mu_values_bytes', 'mu_limbs_bytes',
            'originals_bytes', 'selector_bytes', 'prepared_bytes', 'coefficients_bytes', 'temporary_wire_bytes',
            'local_peak_observed_bytes', 'peak_observed_bytes', 'preparations', 'repetitions'}
    assert set(w) == keys and len(w['preparations']) == len(w['repetitions']) == 2
    assert w['preparations'][r:] == w['repetitions'][r:] == [None]*(2-r)
    retained, coefficient_min = 0, 0
    for j, (mu, layout) in enumerate(zip(v['multiplicities'], s['mu_layouts'])):
        ell, blowup = layout['ell'], layout['blowup']
        col_bits = k+(d.bit_length()-1)-ell
        assert set(mu) == {'certificate', 'wire', 'import_usage'}
        qc, qo, wire = certificate(mu['certificate'], 81+j, ell, col_bits, blowup, d)
        sized(mu['wire'], wire(qc))
        assert set(regs[j]) == {'production', 'verification'}
        registration(regs[j]['production'], regs[j]['verification'], ell, col_bits, blowup, d, qc)
        assert mu['import_usage'] == regs[j]['verification']
        preparation(w['preparations'][j], ell, col_bits, blowup)
        pw = w['preparations'][j]
        retained += pw['encoded_columns_bytes']+pw['merkle_nodes_bytes']
        producer_local += 2*(1 << (col_bits+blowup))-1
        columns = 1 << col_bits
        ids = ([0] if t*d//columns else [])+([1] if t*d % columns else [])
        pieces.append(ids); mu_sizes.append(wire(qo))
        coefficient_min = max(coefficient_min, len(ids)*((1 << ell)+columns)*width)
        consumer_local += len(ids)*qo*(1+col_bits+blowup); queries += len(ids)*qo
        sections += [(f'mu/{j}/root', 32), (f'mu/{j}/certificate', wire(qc))]
    assert set(v['record']) == {'parameters', 'repetitions'}
    assert v['record']['parameters'] == dict(id=71, degree=d, positions=positions, table_rows=t, columns=c,
        group_bits=b, unit_bits=h, repetitions=r, identity_numerator=h+positions+c*t-1)
    assert len(v['record']['repetitions']) == r
    tree_size = lambda z: width*(2+2*z*z+3*z)
    for j, rep in enumerate(v['record']['repetitions']):
        ident = 4*71+2*j
        assert set(rep) == {'lookup', 'table', 'selected', 'originals', 'multiplicities'}
        tree(rep['lookup'], ident, m, d); tree(rep['table'], ident+1, k, d)
        sel = rep['selected']
        assert set(sel) == {'tree_id', 'point', 'claims', 'sc'} and sel['tree_id'] == ident
        assert sel['sc'] == sc(ident, m, d) and len(sel['point']) == m
        for x in sel['point']:
            field(x, d)
        claims(sel['claims'], list(range(41, 41+c)), d)
        assert len(rep['originals']) == c and len(rep['multiplicities']) == len(pieces[j])
        for i, o in enumerate(rep['originals']):
            opening(o, 41+i, v['originals'][i]['certificate'])
        for ident, o in zip(pieces[j], rep['multiplicities']):
            opening(o, ident, v['multiplicities'][j]['certificate'])
        rw = w['repetitions'][j]
        assert isinstance(rw, dict) and set(rw) == {'lookup', 'table', 'selected'}
        fraction(rw['lookup'], m, c, d); fraction(rw['table'], k, c, d); fraction(rw['selected'], m, c, d, True)
        sections += [(f'repetition/{j}/lookup', tree_size(m)), (f'repetition/{j}/table', tree_size(k)),
                     (f'repetition/{j}/selected', width*(4*m+c+2))]
        sections += [(f'repetition/{j}/original/{i}', size) for i, size in enumerate(original_sizes)]
        sections += [(f'repetition/{j}/piece_values', len(pieces[j])*width)]
        sections += [(f'repetition/{j}/piece/{i}', mu_sizes[j]) for i in range(len(pieces[j]))]
    proof = v['proof']
    assert set(proof) == {'wire', 'capacity_bytes', 'sections'} and len(proof['sections']) == len(sections)
    for actual, (name, count) in zip(proof['sections'], sections):
        assert set(actual) == {'name', 'wire'} and actual['name'] == name
        sized(actual['wire'], count)
    for j, mu in enumerate(v['multiplicities']):
        assert mu['wire'] == proof['sections'][2+2*j]['wire']
    size = sum(count for _, count in sections)
    sized(proof['wire'], size)
    assert proof['capacity_bytes'] == w['proof_bytes'] >= size
    assert w['units_bytes'] >= r*h*width and w['index_bytes'] >= 16*t
    assert w['group_weights_bytes'] >= (1 << h)*width
    assert w['mu_values_bytes'] >= r*n*width and w['mu_limbs_bytes'] >= r*n*d*4
    assert w['originals_bytes'] >= c*positions*width and w['selector_bytes'] >= positions*width
    assert w['prepared_bytes'] == retained and w['coefficients_bytes'] >= coefficient_min
    base = sum(w[key] for key in ('proof_bytes', 'units_bytes', 'mu_values_bytes', 'mu_limbs_bytes', 'originals_bytes', 'selector_bytes', 'prepared_bytes'))
    assert w['peak_observed_bytes'] >= w['local_peak_observed_bytes'] >= base
    for rep in w['repetitions'][:r]:
        assert all(w['peak_observed_bytes'] >= base+child['peak_observed_bytes'] for child in rep.values())
    assert w['temporary_wire_bytes'] >= max(mu['wire']['bytes'] for mu in v['multiplicities'])
    PCS.hashes(v['producer_usage']['local'], producer_local); PCS.hashes(v['consumer_usage']['local'], consumer_local)
    u = v['producer_usage']['transcript']
    assert u == v['consumer_usage']['transcript']
    transcript(u, d)
    triangular = lambda z: z*(z-1)//2
    opening_count = r*c+sum(map(len, pieces))
    absorbs = 2+r*(9+4*m+3*k+triangular(m)+triangular(k))+3*opening_count
    draws = r*(h+2+3*m+2*k+triangular(m)+triangular(k))
    assert queries <= u['column_attempts'] <= 64*queries and u['xof_requests'] == draws+u['column_attempts']
    assert u['hash_evaluations'] == 2+absorbs+u['xof_requests']
    framing = v['framing']
    assert set(framing) == {'statement', 'table_metadata', 'table_data', 'selector'}
    name, params = {'scalar': ('range_8', 0), 'grouped': ('exp_q/hi', 4), 'signed': ('exp_q/direct', 3), 'zero': ('exp_q/hi', 4)}[scenario]
    metadata_bytes = len(b'stele/v0.1/table/identity')+8+len(name)+params
    data_bytes = len(b'stele/v0.1/table/data')+41+4*n*c
    sized(framing['table_metadata'], metadata_bytes); sized(framing['table_data'], data_bytes)
    sized(framing['selector'], positions)
    sized(framing['statement'], 35+metadata_bytes+data_bytes+positions+137*c+10*r)
    admission = v['admission']
    assert set(admission) == {'producer_public_bytes', 'producer_dense_elements', 'outer_public_bytes', 'import_public_bytes'}
    assert admission['producer_public_bytes'] == admission['outer_public_bytes']+2*admission['import_public_bytes']
    assert admission['producer_dense_elements'] > 0 and admission['outer_public_bytes'] >= framing['statement']['bytes']
    assert set(v['continuation']) == {'producer', 'consumer'}
    field(v['continuation']['producer'], d)
    assert v['continuation']['producer'] == v['continuation']['consumer']
    diagnostics = v['diagnostics']
    assert set(diagnostics) == {'statement_hashes', 'receipt_digest_evaluations', 'continuations'}
    PCS.hashes(diagnostics['statement_hashes'], 1)
    assert diagnostics['receipt_digest_evaluations'] == 2*c+4+len(sections)+1
    assert set(diagnostics['continuations']) == {'producer', 'consumer'}
    delta = diagnostics['continuations']['producer']
    PCS.hashes(delta)
    assert delta == diagnostics['continuations']['consumer']
    assert {key: delta[key] for key in PCS.HASH_KEYS-{'candidate_words'}} == dict(hash_evaluations=1, xof_requests=1, xof_bytes=256, state_updates=1, column_attempts=0)
    assert d <= delta['candidate_words'] <= 64
    assert set(v['stages_ns']) == stages and all(t > 0 for t in v['stages_ns'].values())
    assert v['total_ns'] >= sum(v['stages_ns'].values()) and v['remainder_ns'] == v['total_ns']-sum(v['stages_ns'].values())


def check_cases(records):
    assert [(r['scenario'], r['field_degree'], r['sample']) for r in records] == CASES


def identity(v):
    return {k: value for k, value in v.items() if k not in {'stages_ns', 'total_ns', 'remainder_ns', 'sample', 'peak_rss_bytes', 'native_time_resource_report'}}


def assemble(metadata, records):
    # Distinct transcript objects only: producer/consumer, each original certificate
    # producer/verifier, each internal mu producer/verifier, and standalone imports.
    transcripts = [u for r in records for u in (
        [r['producer_usage']['transcript'], r['consumer_usage']['transcript']]
        +[h for s in r['originals'] for h in (s['producer'], s['verifier']['transcript'])]
        +[h for s in r['producer_usage']['registrations'] if s is not None
          for h in (s['production'], s['verification']['transcript'])]
        +[s['import_usage']['transcript'] for s in r['multiplicities']])]
    return dict(schema_version=1, kind='micro', workload='micro/conditional-lookup', commit=metadata['commit'],
        toolchain=metadata['toolchain'], device=metadata['device'], driver='not-applicable', model_config=dict(**metadata, samples=records),
        plan_digest=hashlib.sha256(json.dumps(metadata['plan'], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        profile='standard', bindings_all_on=True, batch_size=1, prompt_tokens=0, generated_tokens=0,
        prover_time_ns=sum(r['total_ns'] for r in records), witness_recompute_ns=0,
        stage_times_ns={f'{i}/{s}': t for i, r in enumerate(records) for s, t in (r['stages_ns']|{'remainder': r['remainder_ns']}).items()},
        kernel_counters={
            'disjoint_protocol_transcript_hashes': sum(u['hash_evaluations'] for u in transcripts),
            'diagnostic_continuation_hashes': sum(u['hash_evaluations'] for r in records for u in r['diagnostics']['continuations'].values()),
            'original_preparation_hashes': sum(s['preparation_hashes']['hash_evaluations'] for r in records for s in r['originals']),
            'producer_local_hashes': sum(r['producer_usage']['local']['hash_evaluations'] for r in records),
            'consumer_local_hashes': sum(r['consumer_usage']['local']['hash_evaluations'] for r in records),
            'original_registration_local_hashes': sum(s['verifier']['local']['hash_evaluations'] for r in records for s in r['originals']),
            'internal_mu_registration_local_hashes': sum(s['verification']['local']['hash_evaluations'] for r in records for s in r['producer_usage']['registrations'] if s is not None),
            'standalone_mu_import_local_hashes': sum(s['import_usage']['local']['hash_evaluations'] for r in records for s in r['multiplicities']),
            'diagnostic_hashes': sum(r['diagnostics']['statement_hashes']['hash_evaluations']+r['diagnostics']['receipt_digest_evaluations'] for r in records),
            'actual_a3_gamma_draws': sum(x[key]['accounting']['gamma'] for r in records for x in r['record']['repetitions'] for key in ('lookup', 'table'))},
        proof_size_bytes=0, verifier_time_ns=dict(rust=0, python=0), controls=dict(total=0, passed=0, failed=0),
        note='Complete conditional lookup with actual original registration, producer including mu registration, standalone imports and closed verifier; all bindings on. '
             'Inclusive cleanup, no replay; timings and whole-worker RSS include documented scopes. Component proof sizes and verifier times are in model_config.samples; root inference-summary fields are zero. '
             'Standard is a schema tag; no inference/privacy/profile admission, fitted constant or speedup.')


def main():
    if len(sys.argv) != 2 or (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        raise SystemExit('usage: uv run --no-project --python 3.12 python bench/lookup.py <new-external-ledger.json>')
    output = Path(sys.argv[1]).absolute(); raw = output.with_suffix('.samples')
    if output.exists() or raw.exists() or ROOT in output.resolve().parents or run('git', 'status', '--porcelain'):
        raise SystemExit('requires clean committed source and new external output/sample paths')
    commit, tree = run('git', 'rev-parse', 'HEAD'), run('git', 'rev-parse', 'HEAD^{tree}')
    plan = dict(cases=CASES, workers=1, samples_per_cell=3, build='release',
        sampling='fixed order; no warmup, retries, cache flush or discarded samples',
        shapes={c: shape(c, 'full') for c in ('scalar', 'grouped', 'signed', 'zero')},
        fixture='actual registered Tables; selected joint tuple row=(37*i+11) mod t, scalar row7; every fourth position inactive except scalar; zero all inactive; inactive originals256; source41+i, mu81+j, lookup71; prefix fixed across samples',
        limits=dict(positions=1 << 12, public_bytes=1 << 28, proof_bytes=1 << 28, producer='exact checked Descriptor limits'),
        timing='fixture/Table generation through protocol cleanup; disjoint stages plus remainder; producer includes actual mu preparation/certificate production/verification; excludes build, launch, argument parsing and final JSON serialization',
        memory='fresh-worker whole-process RSS including serialization/runtime/allocator; original messages/preparation/certificates, proof and imported handles retained through verifier; no isolated verifier-memory claim',
        capacities=MEMORY_SCOPE,
        usage='actual distinct original certificate, producer outer/internal registration, standalone import and verifier scopes; continuation deltas and diagnostic hashes separate; cumulative transcript snapshots never added as nested prefixes',
        cost_terms='c_lu: indexing/histograms/trees; c_sc: actual tree/selected SC; c_c: actual registration/openings; T_misc: Table/selector/limbs/framing; timings remain inclusive, no internal mu sub-timing',
        scope='bounded CPU conditional micro; both fields; scalar, grouped partial, ordinary signed, zero selector; shared host with original research workers preserved; no private-plan/Q12/ZK/profile/c_lu fit or comparative speed claim')
    raw.mkdir(parents=True)
    metadata = dict(commit=commit, tree=tree, plan=plan, toolchain=run('rustc', '-Vv'), cargo=run('cargo', '--version'),
                    os=platform.platform(), python=sys.version, device=platform.machine()+' '+run('sysctl', '-n', 'machdep.cpu.brand_string'))
    (raw/'provenance-before-build.json').write_text(json.dumps(metadata, indent=2)+'\n')
    with (raw/'build.log').open('x') as stream:
        subprocess.run(['cargo', 'build', '-p', 'stele-negative-controls', '--example', 'lookup_bench', '--release', '--locked', '--offline'], cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=True)
    binary = ROOT/'target/release/examples/lookup_bench'
    metadata['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    with (raw/'provenance.json').open('x') as stream:
        stream.write(json.dumps(metadata, indent=2)+'\n')
    def unchanged():
        assert run('git', 'rev-parse', 'HEAD') == commit and run('git', 'rev-parse', 'HEAD^{tree}') == tree
        assert not run('git', 'status', '--porcelain') and hashlib.sha256(binary.read_bytes()).hexdigest() == metadata['binary_sha256']
    records = []
    for i, (scenario, d, sample) in enumerate(CASES):
        unchanged(); stats = raw/f'{i:02d}.time.txt'
        result = subprocess.run(['/usr/bin/time', '-l', '-o', str(stats), str(binary), scenario, str(d), 'full'], cwd=ROOT, text=True, capture_output=True)
        for suffix, value in [('stdout', result.stdout), ('stderr', result.stderr), ('exit', str(result.returncode)+'\n')]:
            with (raw/f'{i:02d}.{suffix}').open('x') as stream:
                stream.write(value)
        result.check_returncode(); unchanged(); v = decode(result.stdout); receipt(v, scenario, d)
        report = stats.read_text(); peaks = [int(line.split()[0]) for line in report.splitlines() if 'maximum resident set size' in line]
        assert len(peaks) == 1 and peaks[0] > 0
        records.append(dict(**v, sample=sample, peak_rss_bytes=peaks[0], native_time_resource_report=report))
        print(f'Validated {scenario}/{d}/{sample}', flush=True)
    check_cases(records); unchanged()
    for i in range(0, len(records), 3):
        assert identity(records[i]) == identity(records[i+1]) == identity(records[i+2])
    with output.open('x') as stream:
        json.dump(assemble(metadata, records), stream, separators=(',', ':')); stream.write('\n')
    subprocess.run(['cargo', 'run', '-p', 'stele-bench', '--locked', '--offline', '--', 'ledger', 'validate', str(output)], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
