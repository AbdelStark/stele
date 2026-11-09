"""Write one synthetic-e2e case as model/preparation/scales/artifact files (RFC-0026, task E16-10).

`python3 research/cqis-model-contract/synthetic_extract.py <fixture-dir> <case> <out-dir>`
"""
import json
from pathlib import Path
import sys


def main(fixtures, name, out):
    fixtures, out = Path(fixtures), Path(out)
    raw = (fixtures / 'synthetic-e2e.bin').read_bytes()
    cases = json.loads((fixtures / 'synthetic-e2e.json').read_text())['cases']
    case = next(c for c in cases if c['name'] == name)
    out.mkdir(parents=True, exist_ok=True)
    for key in ('model', 'preparation', 'scales', 'artifact'):
        span = case[key]
        (out / f'{key}.bin').write_bytes(raw[span['offset']:span['offset'] + span['length']])


if __name__ == '__main__':
    main(*sys.argv[1:4])
