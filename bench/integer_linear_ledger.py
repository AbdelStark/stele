"""RFC-0024 §6 and RFC-0018 §1: validate and assemble completed resource evidence.

The sampler runs separately. Assembly requires the entire fixed matrix, preserves
its recorded source, and grants no inference/profile or control-coverage credit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

from integer_linear import CASES, digest, rss
from malloc_trace import require

STAGES = '''fixture original-messages forward-capture prepare-X prepare-W
certificate-X-prove certificate-W-prove certificate-X-import certificate-W-import
range-X-descriptor range-W-descriptor range-X-prove-including-mu-registration
range-W-prove-including-mu-registration range-X-mu-import range-W-mu-import
range-X-verify range-W-verify schema advice-witness prepare-advice
certificate-advice-prove certificate-advice-import expected-output outer-descriptor
producer-transcript outer-prove-including-advice-mu-registration outer-advice-mu-import
verifier-transcript outer-verify following-prove following-verify export-observations'''.split()
ARTIFACTS = set('''request.json reference-time.txt allocation-transport.json native.json
reference.json native-allocations.txt.gz reference-stderr.txt native-time.txt
malloc-history-stderr.txt native-stderr.txt'''.split())
REFERENCE_MANIFEST = Path(__file__).resolve().parents[1]/'tests/negative-controls/fixtures/integer-linear/manifest.json'
REFERENCE_DIGEST = '83bdafdeb83dbf9c0f4fea6755d6f5f8f9bec942bbbaa5c85044b31549ab8eaf'


def invalid_number(value):
    raise ValueError(f'Non-integer JSON number: {value}')


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'Duplicate JSON key')
        out[key] = value
    return out


def read(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique,
                      parse_float=invalid_number, parse_constant=invalid_number)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def same(actual, expected, reason):
    require(canonical(actual) == canonical(expected), reason)


def positive(value, reason):
    require(type(value) is int and value > 0, reason)


def observation(directory):
    comparison = read(directory/'comparison.json')
    require(set(comparison['artifacts']) == ARTIFACTS, 'Complete worker artifact inventory')
    for name, expected in comparison['artifacts'].items():
        require(digest(directory/name) == expected, f'Changed worker artifact: {name}')
    native, reference, request = (read(directory/name) for name in ('native.json','reference.json','request.json'))
    same(request, native['request'], 'Native request identity')
    same(native['verification'], reference['verification'], 'Complete independent consumption')
    require(reference['measurement']['request_sha256'] == digest(directory/'request.json'), 'Reference input identity')
    verification = native['verification']
    require(verification['decision'] == 'accept' and verification['record'] is not None
            and set(verification['continuation']) == {'record','usage','probe'}, 'Complete accepted continuation')
    same(native['producer_usage']['transcript'], verification['usage']['transcript'], 'Outer transcript usage')
    for produced, imported in zip([*native['range_producer_usage'], native['producer_usage']],
            [*verification['imports']['original_multiplicities'], verification['imports']['multiplicities']], strict=True):
        same([None if v is None else v['verification'] for v in produced['registrations']],
             imported, 'Actual multiplicity registration imports')
    d, r = request['degree'], request['repetitions']
    require((d, r) == (comparison['degree'], comparison['repetitions'])
            and d in (4, 8) and r in (1, 2), 'Field/repetition identity')
    # Benchmark case identity only: both actual consumers have already run.
    require(digest(REFERENCE_MANIFEST) == REFERENCE_DIGEST, 'Qualified positive inventory')
    positives = {v['name']:v['request_sha256'] for v in read(REFERENCE_MANIFEST)['groups']['positive']}
    require(fingerprint(request) == positives[f'{comparison["case"]}-k{d}-r{r}'],
            'Independent positive request identity')
    h, a, b, c = request['dims']
    for work, elements in zip(native['online_originals'], (1 << (h+a+b), 1 << (h+c+b)), strict=True):
        same(work, dict(source_visits=1, source_elements=elements, retained_bytes=(1 << (h+b))*4*d),
             'One actual online original visit')
    same(native['capture'], dict(source_elements=[1 << (h+a+b+c)]*2, accumulators=1 << (h+a+c)), 'Forward capture')
    same(comparison['online_originals'], native['online_originals'], 'Recorded online work')
    sizes = native['bytes']
    def size(raw):
        return len(bytes.fromhex(raw))
    original_sizes = [size(v['certificate_hex']) for v in request['originals']]
    range_sizes = [size(v['range_proof_hex']) for v in request['originals']]
    require(sizes['original_certificates'] == original_sizes and sizes['original_ranges'] == range_sizes
            and sizes['outer'] == size(request['proof_hex']) and sizes['following'] == size(request['following_hex'])
            and sizes['complete_transmitted'] == sum(original_sizes+range_sizes)+sizes['outer']+sizes['following'],
            'Complete transmitted bytes')
    same(comparison['bytes'], sizes, 'Recorded wire sizes')

    measurement = native['measurement']
    same(comparison['native_measurement'], measurement, 'Recorded native stages')
    require(measurement['trace'] is True and set(measurement['stages_ns']) == set(STAGES), 'Complete native stage inventory')
    for elapsed in measurement['stages_ns'].values():
        positive(elapsed, 'Native stage time')
    require(measurement['total_ns'] == sum(measurement['stages_ns'].values())+measurement['remainder_ns']
            and type(measurement['remainder_ns']) is int and measurement['remainder_ns'] >= 0, 'Native timing partition')
    markers = measurement['markers']
    names = ['pipeline/begin']+[f'{name}/{edge}' for name in STAGES for edge in ('begin','end')]+['pipeline/end']
    require([m['name'] for m in markers] == names and len({m['address'] for m in markers}) == len(names), 'Ordered retained markers')
    memory = comparison['native_memory']
    require(len(memory['stages']) == len(names)-1, 'Complete allocation intervals')
    for interval, start, end in zip(memory['stages'], names[:-1], names[1:], strict=True):
        require((interval['start_marker'], interval['end_marker']) == (start, end)
                and interval['peak_heap_requested_bytes'] >= max(interval['start_heap_requested_bytes'],
                                                                interval['end_heap_requested_bytes']), 'Allocation interval')
    require(memory['pipeline_peak_heap_requested_bytes'] == max(v['peak_heap_requested_bytes'] for v in memory['stages'])
            and memory['heap_requested_peak_bytes'] >= memory['pipeline_peak_heap_requested_bytes'], 'Simultaneous allocation peak')
    require(memory['peak_rss_bytes'] == rss(directory/'native-time.txt'), 'Native worker RSS')
    py = reference['measurement']
    require(py['total_ns'] == py['load_ns']+py['closed_request_ns']
            and py['python_managed_peak_bytes'] >= py['python_managed_current_bytes'] >= 0, 'Reference scopes')
    for name in ('load_ns','closed_request_ns','total_ns','python_managed_peak_bytes'):
        positive(py[name], 'Reference measurement')
    same(comparison['reference_memory'], dict(**py, peak_rss_bytes=rss(directory/'reference-time.txt'),
         process_wall_ns=comparison['reference_memory']['process_wall_ns']), 'Reference worker observations')

    # Full equality precedes compaction; immutable raw artifacts retain every value.
    result = {k:v for k,v in native.items() if k not in ('request','verification','measurement')}
    result.update(case=comparison['case'], degree=d, repetitions=r,
        statement={k:v for k,v in request.items() if k not in ('proof_hex','following_hex','originals')},
        originals=[{k:v for k,v in source.items() if k not in ('certificate_hex','range_proof_hex')} for source in request['originals']],
        native_measurement={k:v for k,v in measurement.items() if k not in ('markers','worker_pid')},
        native_memory=memory, reference_memory=comparison['reference_memory'],
        verification=dict(decision='accept', imports=verification['imports'], outer_usage=verification['usage'],
            original_range_usage=[v['usage'] for v in verification['original_ranges']],
            point_equality=verification['record']['equality'], continuation_usage=verification['continuation']['usage'],
            request_sha256=fingerprint(request), complete_result_sha256=fingerprint(verification)),
        artifacts=comparison['artifacts'], comparison_sha256=digest(directory/'comparison.json'), directory=str(directory))
    return result, comparison


def assemble(directory, host_context='Host contention was not measured.'):
    require((directory/'summary.json').is_file(), 'Resource campaign is incomplete')
    summary, metadata = read(directory/'summary.json'), read(directory/'metadata.json')
    same(summary['metadata'], metadata, 'Campaign metadata')
    same(summary['samples'], read(directory/'completed.json'), 'Completed campaign inventory')
    same(metadata['plan']['cases'], CASES, 'Fixed resource matrix')
    require(len(summary['samples']) == len(CASES) and (directory/'build.exit').read_text() == '0\n', 'Complete successful matrix')
    samples, sources, binary = [], None, None
    for index, ((case, degree, repetitions), item) in enumerate(zip(CASES, summary['samples'], strict=True)):
        sample = directory/f'{index:02d}-{case}-k{degree}-r{repetitions}'
        require(Path(item['path']).resolve() == (sample/'comparison.json').resolve()
                and digest(sample/'comparison.json') == item['sha256'], 'Campaign sample identity')
        value, comparison = observation(sample)
        require((value['case'],value['degree'],value['repetitions']) == (case,degree,repetitions)
                and comparison['source_head'] == metadata['commit'], 'Measured source and case')
        if sources is None:
            sources, binary = comparison['sources'], comparison['binary']
        same(comparison['sources'], sources, 'Campaign source inventory changed')
        same(comparison['binary'], binary, 'Campaign native binary changed')
        samples.append(value)
    path = Path(binary['path'])
    require(path.name == 'integer_linear_bench' and digest(path) == binary['sha256'], 'Measured native binary identity')
    stages = {}
    for index, sample in enumerate(samples):
        native = sample['native_measurement']
        stages.update({f'{index}/native/{name}':elapsed for name,elapsed in
                       (native['stages_ns']|{'remainder':native['remainder_ns']}).items()})
        stages.update({f'{index}/python/{name}':sample['reference_memory'][name]
                       for name in ('load_ns','closed_request_ns')})
    return dict(schema_version=1, kind='micro', workload='micro/integer-linear', commit=metadata['commit'],
        toolchain=metadata['toolchain'], device=metadata['device'], driver='not-applicable',
        model_config=dict(metadata=metadata, source_sha256=sources, binary=binary, samples=samples,
            positive_reference_manifest_sha256=REFERENCE_DIGEST,
            campaign_artifacts={name:digest(directory/name) for name in
                                ('metadata.json','build.jsonl','build.stderr','build.exit','completed.json','summary.json')},
            assembler_source_sha256=digest(Path(__file__)),
            host_context=host_context),
        plan_digest=fingerprint(metadata['plan']), profile='standard', bindings_all_on=True, batch_size=1,
        prompt_tokens=0, generated_tokens=0, prover_time_ns=sum(stages.values()),
        witness_recompute_ns=sum(v['native_measurement']['stages_ns'][name] for v in samples
                                 for name in ('forward-capture','advice-witness')), stage_times_ns=stages,
        kernel_counters=dict(outer_producer_local_hashes=sum(v['producer_usage']['non_transcript']['hash_evaluations'] for v in samples)),
        proof_size_bytes=0, verifier_time_ns=dict(rust=0,python=0), controls=dict(total=0,passed=0,failed=0),
        note='Complete bounded RFC-0024 resource matrix with all bindings enabled. Instrumented native phases and '
             'independent closed-request timings retain profiler overhead; no uninstrumented performance comparison '
             'or fitted constant. Capture and advice generation are separate stages and sum to witness_recompute_ns. '
             'Native simultaneous malloc requests, Python-managed allocations and both whole-worker RSS values have '
             'separate scopes. Native process wall includes allocation-collection pause. Component bytes, Usage and '
             'continuations remain in samples/raw artifacts; no inference, privacy, profile, W8 or control-count credit. '
             'Standard is the ledger schema tag only.')


if __name__ == '__main__':
    require(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'Python 3.12 without optimization required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--check-sample', action='store_true')
    parser.add_argument('--host-context', default='Host contention was not measured.')
    args = parser.parse_args()
    if args.check_sample:
        require(args.output is None, 'Sample checks write no ledger')
        value, _ = observation(args.directory.resolve())
        print(f'complete sample validated: {value["case"]} K{value["degree"]} r{value["repetitions"]}')
    else:
        require(args.output is not None, 'A new output path is required')
        value = assemble(args.directory.resolve(), args.host_context)
        raw = canonical(value)+b'\n'
        require(len(raw) <= 1 << 20, 'Ledger byte limit')
        with args.output.open('xb') as output:
            output.write(raw)
        print('ledger assembled; validate it with stele-bench ledger validate')
