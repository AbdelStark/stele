"""RFC-0024 §6: replay exported native controls through both closed consumers.

This explicit qualification command is not a default CI campaign. Native
ProverHook executions supply the packets; the independent verifier reconstructs
all authorities from their bytes. Identical requests are consumed once, while
every original control observation must match that actual consumption.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import shutil

from integer_linear_reference import load, need, verify_request

CONTROLS = {306: 4, 307: 8, 312: 2, 314: 2, 316: 2,
            317: 2, 318: 2, 606: 4, 610: 16, 611: 4}
ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def qualify(binary, directory, degree, exports=None):
    directory.mkdir(parents=True, exist_ok=False)
    # Exact source and binary provenance; never read unrelated checkout files.
    paths = sorted({*ROOT.glob('crates/stele-*/src/**/*.rs'),
                    *ROOT.glob('tests/negative-controls/**/*.rs'),
                    *ROOT.glob('tests/negative-controls/*.py'),
                    ROOT/'Cargo.lock'})
    sources = {str(p.relative_to(ROOT)): digest(p) for p in paths}
    binary_hash = digest(binary)
    events, requests, indexes = [], [], {}
    for control, count in CONTROLS.items():
        path = directory/f'native-{control}.jsonl'
        if exports is None:
            with path.open('wb') as output, path.with_suffix('.stderr').open('wb') as errors:
                subprocess.run([str(binary), '--controls', str(degree), str(control)],
                               stdout=output, stderr=errors, check=True)
        else:
            shutil.copyfile(exports/path.name, path)
        exported = [json.loads(line) for line in path.read_text().splitlines()]
        need(len(exported) == 2*count, f'Control{control}AttemptCount')
        need(sum(e['observed']['decision'] == 'accept' for e in exported) == count,
             f'Control{control}AcceptedBaselines')
        for event in exported:
            need(event['control'] == control and event['request']['degree'] == degree,
                 'ExportIdentity')
            key = canonical(event['request'])
            if key not in indexes:
                indexes[key] = len(requests)
                requests.append(event['request'])
            events.append(dict(control=control, side=event['side'], variant=event['variant'],
                               request=indexes[key], observed=event['observed']))
        print(f'K{degree} NC-{control:04}: {count} baselines and {count} rejections exported', flush=True)
    request_path = directory/'requests.jsonl'
    request_path.write_text(''.join(canonical(v)+'\n' for v in requests))
    native_path = directory/'native.jsonl'
    with request_path.open('rb') as input_, native_path.open('wb') as output, \
            (directory/'native.stderr').open('wb') as errors:
        subprocess.run([str(binary), '--verify'], stdin=input_, stdout=output,
                       stderr=errors, check=True)
    native = [json.loads(line) for line in native_path.read_text().splitlines()]
    need(len(native) == len(requests), 'NativeResponseCount')
    for event in events:
        result = native[event['request']]
        need(event['observed'] == {k: result[k] for k in ('decision', 'usage')},
             'ActualControlFailurePrefix')
    with load() as ref, (directory/'reference.jsonl').open('w') as output:
        for index, (request, expected) in enumerate(zip(requests, native, strict=True)):
            actual = json.loads(canonical(verify_request(ref, request)))
            output.write(canonical(actual)+'\n')
            output.flush()
            need(actual == expected, f'CompleteNativeReferenceParity/{index}')
            # Certificates remain alive throughout each attempt; discard only after comparison.
            ref.o.CREATED.clear()
            print(f'K{degree} request {index+1}/{len(requests)}: exact imports, outcome and usage', flush=True)
    need(digest(binary) == binary_hash, 'BinaryChanged')
    need(all(digest(ROOT/p) == value for p, value in sources.items()), 'SourceChanged')
    artifacts = {p.name: digest(p) for p in sorted(directory.iterdir()) if p.is_file()}
    summary = dict(scope='native-generated controls; independent complete consumption; no independent '
                   'adversarial production or resource qualification', degree=degree,
                   binary=dict(path=str(binary), sha256=binary_hash), sources=sources,
                   native_exports='generated' if exports is None else str(exports),
                   attempts=len(events), rejections=sum(CONTROLS.values()),
                   unique_requests=len(requests), events=events, artifacts=artifacts)
    (directory/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')


if __name__ == '__main__':
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'Runtime')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('directory', type=Path)
    parser.add_argument('degree', type=int, choices=(4, 8))
    parser.add_argument('--exports', type=Path, help='replay saved native exports; both consumers still run')
    args = parser.parse_args()
    qualify(args.binary.resolve(), args.directory.resolve(), args.degree,
            None if args.exports is None else args.exports.resolve())
