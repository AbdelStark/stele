"""RFC-0014 §5: export only the complete public shape inventory from a ledger."""
from collections import Counter
import json
from pathlib import Path
import sys
from stage_inventory import shape_record


def export(ledger):
    if ledger.get('bindings_all_on') is not True:
        raise ValueError('all bindings must be on')
    inventory = ledger['model_config']['stage_inventory']
    declared, shapes = inventory['declared'], inventory['shapes']
    if declared['field'] != 4 or not 1 <= len(shapes) <= 256:
        raise ValueError('unsupported field or inventory size')
    lines, counts, seen = [], Counter(), set()
    keys = {'kind', 'field', 'variables', 'degree', 'masks', 'terms', 'compact', 'count'}
    for s in shapes:
        if set(s) != keys or type(s['count']) is not int or s['count'] <= 0 or s['field'] != 4:
            raise ValueError('invalid shape metadata')
        masks = ','.join('-' if v is None else str(v) for v in s['masks'])
        terms = ','.join('.'.join(map(str, t)) or '-' for t in s['terms'])
        line = (f"shape {s['kind']} field={s['field']} vars={s['variables']} "
                f"degree={s['degree']} masks={masks} terms={terms} compact={int(s['compact'])}")
        if (type(s['compact']) is not bool or
                shape_record(line) != {k: v for k, v in s.items() if k != 'count'} or line in seen):
            raise ValueError('invalid or duplicated shape')
        seen.add(line)
        lines.append(line)
        counts['relations' if s['kind'] == 'relation' else 'gkr'] += s['count']
    if any(counts[k] != declared[k] for k in ('relations', 'gkr')):
        raise ValueError('shape counts differ from the declared plan')
    return f'masked-shapes-v1 {len(lines)}\n' + '\n'.join(lines) + '\n'


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: masked_inventory.py validated-ledger.json')
    print(export(json.loads(Path(sys.argv[1]).read_text())), end='')
