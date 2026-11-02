"""Offline scalar control witness data, never proof execution.

Requires the pinned frozen RFC-0023 helper as an explicit input. CI consumes the
checked-in output only. This does not invoke run.py, Protocol or any proof engine.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
SCHEMA_HASH = '7094cf8c92538ea46a16e65540412fe9863e6d46c100f31153e2b8275d73cd1c'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', required=True, type=Path)
    args = parser.parse_args()
    helper = args.helper.resolve()
    assert digest(helper/'schema.py') == SCHEMA_HASH
    assert digest(helper/'controls.py') == '0fadc890304556eb61b1be0d854aa2430df8d79f531eba2f460895220261d2b1'
    pins = json.loads((helper/'source-pins.json').read_text())
    for name in ('requant.py', 'encoding.py', 'limbs.py'):
        path = f'research/cqis-bounds/{name}'
        assert digest(ROOT/path) == pins[path], path
    sys.path[:0] = [str(helper), str(ROOT/'research/cqis-bounds')]
    schema = importlib.import_module('schema')
    req = importlib.import_module('requant')
    encoding = importlib.import_module('encoding')
    controls = importlib.import_module('controls')
    ref = SimpleNamespace(req=req, encoding=encoding)
    cases = {}
    for name, acc, shift in [('zero-0', 0, 0), ('zero-31', 0, 31),
                             ('p-31', 2147483647, 31), ('one-0', 1, 0),
                             ('tie-negative', -1, 1), ('tie-positive', 1, 1)]:
        s = schema.Schema(ref, 1, shift, 8, 1, stage=31)
        source, advice = s.witness([acc])
        values = [1]+[r[0] for r in source+advice]
        for label, terms in s.constraints:
            total = 0
            for coefficient, factors in terms:
                value = coefficient
                for factor in factors:
                    value *= values[factor]
                total += value
            assert total == 0, (name, label, total)
        cases[name] = dict(accumulator=acc, mantissa=1, shift=shift, bits=8,
                           input=[r[0] for r in source], advice=[r[0] for r in advice],
                           output=req.witness(s.spec, acc)['output'])
    s = schema.Schema(ref, 1, 0, 8, 1, stage=31)
    source, advice, output = controls.high_tail(s)
    cases['high-tail'] = dict(accumulator=65537, mantissa=1, shift=0, bits=8,
                             input=[r[0] for r in source], advice=[r[0] for r in advice], output=output)
    frozen_scalar = ROOT/'tests/negative-controls/fixtures/requant/scalar-K4.json'
    scalar = json.loads(frozen_scalar.read_text())
    claims = scalar['expected']['records']['zero']['claims']
    assert all(v[2][1:] == [0, 0, 0] for v in claims)
    cases['negative-h'] = dict(accumulator=-128, mantissa=1, shift=0, bits=8,
                              input=[v[2][0] for v in claims[1:5]],
                              advice=[v[2][0] for v in claims[5:]], output=-128)
    sources = {'frozen/schema.py': SCHEMA_HASH, 'frozen/controls.py': digest(helper/'controls.py'),
               'tests/negative-controls/fixtures/requant/scalar-K4.json': digest(frozen_scalar)}
    for module in list(sys.modules.values()):
        file = getattr(module, '__file__', None)
        if file and Path(file).resolve().is_relative_to(ROOT):
            file = Path(file).resolve()
            sources[str(file.relative_to(ROOT))] = digest(file)
    for name, case in cases.items():
        payload = bytes(case['advice'])
        binary = ROOT/f'tests/negative-controls/fixtures/requant/control-{name}.bin'
        if binary.exists():
            assert binary.read_bytes() == payload
        else:
            binary.write_bytes(payload)
        case['advice_sha256'] = digest(binary)
    result = dict(qualification='Six honest scalar witness constructions, one false high-tail construction and one frozen scalar projection; no proof or verifier run.',
                  sources=sources, cases=cases)
    output = ROOT/'tests/negative-controls/fixtures/requant/control-witnesses.json'
    raw = json.dumps(result, indent=2, sort_keys=True)+'\n'
    if output.exists():
        assert output.read_text() == raw, 'existing fixture differs'
    else:
        output.write_text(raw)
    print(f'8 scalar witness fixtures; SHA256 {digest(output)}; no proof execution')


if __name__ == '__main__':
    main()
