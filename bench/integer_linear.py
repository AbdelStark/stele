"""RFC-0024 §6: complete native attempt, independent consumer and memory evidence.

The traced run is a resource observation, not an uninstrumented performance
claim. Run one case in a fresh directory, or use --campaign DIRECTORY for the
fixed matrix from clean committed source. Historical campaigns are not rerun.
"""
import argparse
import gzip
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from time import perf_counter_ns

from malloc_trace import summarize, require

ROOT = Path(__file__).resolve().parents[1]
CASES = ([(case, d, r) for case in ('scalar', 'stacked') for d in (4, 8) for r in (1, 2)]
         + [(case, d, r) for d in (4, 8) for case, r in (
             ('ties', 1), ('zero_x', 2), ('zero_w', 1), ('wide', 2), ('shift62', 1),
             ('int16_min', 2), ('int16_max', 1), ('int8_min', 2), ('int8_max', 1), ('cap', 2))])


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def reference_worker(path):
    import tracemalloc
    tracemalloc.start(1)
    start = perf_counter_ns()
    sys.path.insert(0, str(ROOT/'tests/negative-controls'))
    from integer_linear_reference import load, verify_request
    raw = path.read_bytes()
    request = json.loads(raw)
    with load() as ref:
        loaded = perf_counter_ns()
        result = verify_request(ref, request)
        verified = perf_counter_ns()
    current, peak = tracemalloc.get_traced_memory()
    print(json.dumps(dict(verification=result, measurement=dict(
        request_sha256=hashlib.sha256(raw).hexdigest(), load_ns=loaded-start,
        closed_request_ns=verified-loaded, total_ns=verified-start,
        python_managed_current_bytes=current, python_managed_peak_bytes=peak,
        memory_scope='Python-managed allocations since worker protocol setup through closed consumer '
        'projection; excludes interpreter startup, native extension allocations and final JSON output; '
        'whole-worker RSS is separate')), separators=(',', ':')))


def rss(path):
    matches = re.findall(r'^\s*(\d+)\s+maximum resident set size\s*$', path.read_text(), re.M)
    require(len(matches) == 1, 'Missing macOS peak RSS')
    return int(matches[0])


def trace_diagnostics(directory):
    require(not (directory/'malloc-history-stderr.txt').read_text().strip(),
            'Allocation history diagnostics require review')
    lines = (directory/'native-stderr.txt').read_text().splitlines()
    for line in lines:
        # macOS reports this known profiler overhead separately from event loss.
        if 'could not tag MSL-related memory as no_footprint' in line:
            continue
        require(not re.search(r'dropped|lost|truncat|overflow|failed|error|corrupt|cannot|could not',
                              line, re.I), 'Allocation recorder diagnostics require review')
    return lines


def record_allocations(pid, path, diagnostics):
    """Preserve every byte losslessly without retaining multi-gigabyte text files."""
    checksum, size = hashlib.sha256(), 0
    with diagnostics.open('wb') as errors, path.open('wb') as destination:
        process = subprocess.Popen(['/usr/bin/malloc_history', str(pid), '-allEvents'],
                                   stdout=subprocess.PIPE, stderr=errors)
        try:
            with gzip.GzipFile(fileobj=destination, mode='wb', filename='', mtime=0) as archive:
                while block := process.stdout.read(1 << 20):
                    checksum.update(block)
                    size += len(block)
                    archive.write(block)
        finally:
            process.stdout.close()
            process.wait()
        require(process.returncode == 0, 'Allocation history failed')
    return dict(format='gzip', uncompressed_bytes=size, uncompressed_sha256=checksum.hexdigest())


def native_worker(binary, directory, degree, case, repetitions):
    logs = directory/'malloc-logs'
    logs.mkdir()
    environment = os.environ.copy()
    environment.pop('MallocStackLogging', None)
    environment['MallocStackLoggingNoCompact'] = '1'
    environment['MallocStackLoggingDirectory'] = str(logs)
    report = directory/'native-time.txt'
    errors = directory/'native-stderr.txt'
    command = ['/usr/bin/time', '-l', '-o', str(report), str(binary), str(degree), case,
               str(repetitions), '--trace']
    started = perf_counter_ns()
    with errors.open('wb') as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=stderr)
        try:
            raw = process.stdout.readline()
            require(bool(raw), 'Native worker produced no observation')
            (directory/'native.json').write_bytes(raw)
            native = json.loads(raw)
            pid = native['measurement']['worker_pid']
            require(type(pid) is int and pid > 0, 'Native PID')
            # Inspect only the worker just launched by this command.
            parent = int(subprocess.check_output(['/bin/ps', '-o', 'ppid=', '-p', str(pid)]))
            require(parent == process.pid or pid == process.pid, 'Worker ownership')
            print(f'native worker {pid}: complete proof accepted; collecting allocation events', flush=True)
            collecting = perf_counter_ns()
            transport = record_allocations(pid, directory/'native-allocations.txt.gz',
                                           directory/'malloc-history-stderr.txt')
            collection_ns = perf_counter_ns()-collecting
            (directory/'allocation-transport.json').write_text(json.dumps(transport)+'\n')
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write(b'continue\n')
                    process.stdin.flush()
                except BrokenPipeError:
                    pass
            process.stdin.close()
            process.wait()
        require(process.returncode == 0, 'Native worker failed')
        require(not process.stdout.read().strip(), 'Unexpected native output')
    process_ns = perf_counter_ns()-started
    diagnostics = trace_diagnostics(directory)
    memory = summarize(directory/'native-allocations.txt.gz', native['measurement']['markers'])
    require(native['measurement']['trace'] is True, 'Untraced native attempt')
    require(native['measurement']['markers'][0]['name'] == 'pipeline/begin'
            and native['measurement']['markers'][-1]['name'] == 'pipeline/end', 'Pipeline markers')
    memory['pipeline_peak_heap_requested_bytes'] = max(s['peak_heap_requested_bytes'] for s in memory['stages'])
    memory['peak_rss_bytes'] = rss(report)
    memory['recorder_diagnostics'] = diagnostics
    memory['rss_scope'] = 'whole worker including runtime, tracing overhead, serialization and teardown'
    memory['process_wall_ns'] = process_ns
    memory['allocation_collection_ns'] = collection_ns
    memory['wall_scope'] = 'includes the pause for allocation collection; use internal phases for executed work'
    return native, memory


def qualify(binary, directory, degree, case, repetitions, expected):
    require(sys.platform == 'darwin', 'This allocation recorder requires macOS')
    directory.mkdir(parents=True, exist_ok=False)
    def source_paths():
        return sorted({*ROOT.glob('crates/stele-*/src/**/*.rs'), *ROOT.glob('research/**/*.py'),
                    *ROOT.glob('tests/negative-controls/**/*.rs'),
                    *ROOT.glob('tests/negative-controls/**/*.py'), *ROOT.glob('bench/*.py'),
                    *ROOT.glob('crates/stele-*/Cargo.toml'),
                    ROOT/'tests/negative-controls/Cargo.toml', ROOT/'Cargo.toml', ROOT/'Cargo.lock'})
    paths = source_paths()
    sources = {str(p.relative_to(ROOT)): digest(p) for p in paths}
    binary_hash = digest(binary)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    native, memory = native_worker(binary, directory, degree, case, repetitions)
    if expected is not None:
        previous = json.loads(expected.read_bytes())
        for key in ('request', 'verification', 'producer_usage'):
            require(native[key] == previous[key], f'Preserved {key}')
    request = directory/'request.json'
    request.write_text(json.dumps(native['request'], sort_keys=True, separators=(',', ':'))+'\n')
    print('native request and observations preserved; running independent closed consumer', flush=True)
    reference_path = directory/'reference.json'
    reference_start = perf_counter_ns()
    with reference_path.open('wb') as output, (directory/'reference-stderr.txt').open('wb') as errors:
        subprocess.run(['/usr/bin/time', '-l', '-o', str(directory/'reference-time.txt'),
                        sys.executable, '-B', str(Path(__file__).resolve()), '--reference-worker', str(request)],
                       cwd=ROOT, stdout=output, stderr=errors, check=True)
    reference_wall = perf_counter_ns()-reference_start
    reference = json.loads(reference_path.read_bytes())
    require(reference['verification'] == native['verification'], 'Complete native/reference mismatch')
    require(reference['measurement']['request_sha256'] == digest(request), 'Reference input mismatch')
    q = native['request']
    require((q['degree'], q['repetitions']) == (degree, repetitions), 'Case identity')
    h, a, b, c = q['dims']
    for work, elements in zip(native['online_originals'], (1 << (h+a+b), 1 << (h+c+b)), strict=True):
        require(work == dict(source_visits=1, source_elements=elements, retained_bytes=(1 << (h+b))*4*degree),
                'Actual retained-row work')
    require(native['capture'] == dict(source_elements=[1 << (h+a+b+c)]*2,
                                     accumulators=1 << (h+a+c)), 'Actual forward capture')
    sizes = native['bytes']
    require(sizes['complete_transmitted'] == sum(sizes['original_certificates'])
            + sum(sizes['original_ranges']) + sizes['outer'] + sizes['following'], 'Wire accounting')
    require(digest(binary) == binary_hash, 'Native binary changed')
    require(source_paths() == paths and all(digest(ROOT/p) == h for p, h in sources.items()), 'Source changed')
    result = dict(scope='development resource evidence; bounded fixed operation with all bindings enabled; '
                  'not configured inference or profile qualification', degree=degree, case=case,
                  repetitions=repetitions, source_head=head, sources=sources,
                  binary=dict(path=str(binary), sha256=binary_hash),
                  native_memory=memory, reference_memory=dict(peak_rss_bytes=rss(directory/'reference-time.txt'),
                  process_wall_ns=reference_wall, **reference['measurement']), bytes=sizes,
                  native_reference='exact complete imports, claims, records, usage and continuation',
                  native_measurement=native['measurement'], online_originals=native['online_originals'],
                  artifacts={p.name: digest(p) for p in directory.iterdir() if p.is_file()})
    (directory/'comparison.json').write_text(json.dumps(result, indent=2)+'\n')
    print('complete attempt, independent consumption and scoped allocation/RSS observations agree', flush=True)


def campaign(directory):
    """Fixed sequential resource matrix; failed or completed attempts are never retried."""
    def run(*command):
        return subprocess.check_output(command, cwd=ROOT, text=True).strip()

    require(sys.platform == 'darwin' and platform.machine() == 'arm64', 'macOS arm64 required')
    require(version('blake3') == '1.0.11', 'Pinned Python blake3 required')
    require(ROOT not in directory.parents and directory != ROOT, 'External campaign directory required')
    require(not run('git', 'status', '--porcelain'), 'Clean committed source required')
    directory.mkdir(parents=True, exist_ok=False)
    plan = dict(cases=CASES, workers=1, samples_per_cell=1,
                sampling='fixed order; fresh native and Python workers; no warmup, retry or discarded sample',
                scope='bounded RFC-0024 operation; all bindings on; no inference/profile/privacy/W8 credit',
                timing='instrumented resource observations, not uninstrumented performance or fitted constants',
                memory='native simultaneous malloc request payloads and Python-managed allocations; '
                       'each complete worker RSS separate; tracer/runtime overhead retained',
                context='fixed scalar and nonconstant stacked matrices plus signed/tie/zero/parameter boundaries; '
                        'no prompt or generated token context')
    metadata = dict(commit=run('git', 'rev-parse', 'HEAD'), tree=run('git', 'rev-parse', 'HEAD^{tree}'),
                    plan=plan, toolchain=run('rustc', '-Vv'), cargo=run('cargo', '--version'),
                    device=platform.machine()+' '+run('sysctl', '-n', 'machdep.cpu.brand_string'),
                    os=platform.platform(), python=sys.version, python_executable=sys.executable,
                    python_blake3=version('blake3'), uv=run('uv', '--version'), directory=str(directory))
    command = ['cargo', 'build', '-p', 'stele-negative-controls', '--example', 'integer_linear_bench',
               '--profile', 'test', '--locked', '--offline', '--message-format=json-render-diagnostics']
    metadata['build_command'] = command
    (directory/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    with (directory/'build.jsonl').open('wb') as output, (directory/'build.stderr').open('wb') as errors:
        built = subprocess.run(command, cwd=ROOT, stdout=output, stderr=errors)
    (directory/'build.exit').write_text(str(built.returncode)+'\n')
    built.check_returncode()
    artifacts = [json.loads(line) for line in (directory/'build.jsonl').read_bytes().splitlines()]
    binaries = {a['executable'] for a in artifacts if a.get('reason') == 'compiler-artifact'
                and a['target']['name'] == 'integer_linear_bench' and a['target']['kind'] == ['example']}
    require(len(binaries) == 1 and None not in binaries, 'Unique native artifact required')
    binary = Path(binaries.pop()).resolve()
    results = []
    for index, (case, degree, repetitions) in enumerate(CASES):
        require(run('git', 'rev-parse', 'HEAD') == metadata['commit']
                and not run('git', 'status', '--porcelain'), 'Campaign source changed')
        sample = directory/f'{index:02d}-{case}-k{degree}-r{repetitions}'
        print(f'case {index+1}/{len(CASES)}: {case} K{degree} r{repetitions}', flush=True)
        qualify(binary, sample, degree, case, repetitions, None)
        results.append(dict(path=str(sample/'comparison.json'), sha256=digest(sample/'comparison.json')))
        (directory/'completed.json').write_text(json.dumps(results, indent=2)+'\n')
    require(run('git', 'rev-parse', 'HEAD') == metadata['commit']
            and not run('git', 'status', '--porcelain'), 'Campaign source changed')
    (directory/'summary.json').write_text(json.dumps(dict(metadata=metadata, samples=results), indent=2)+'\n')
    print('fixed resource matrix complete; raw observations require ledger assembly and validation', flush=True)


if __name__ == '__main__':
    require(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'Python 3.12 without optimization required')
    if len(sys.argv) == 3 and sys.argv[1] == '--reference-worker':
        reference_worker(Path(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] == '--campaign':
        campaign(Path(sys.argv[2]).resolve())
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('binary', type=Path)
        parser.add_argument('directory', type=Path)
        parser.add_argument('degree', type=int, choices=(4, 8))
        parser.add_argument('case')
        parser.add_argument('repetitions', type=int, choices=(1, 2))
        parser.add_argument('--expected', type=Path, help='previous complete native artifact to preserve')
        args = parser.parse_args()
        qualify(args.binary.resolve(), args.directory.resolve(), args.degree,
                args.case, args.repetitions, args.expected)
