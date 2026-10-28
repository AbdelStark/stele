"""Q20 candidate descriptor bytes; research checks, not production binding credit."""
import struct
from statement import encode, decode, P


def scalar(value, d):
    return (value,)+(0,)*(d-1)


def fixture(d, kind=0, order=0, selected=False):
    layout = [(1, 2), (2, 3), (2, 3)]
    coefficient = dict(kind=kind, selectors=[None]*3, axes=[], source_id=None, values=[], width=None)
    if selected:
        coefficient['selectors'] = [[scalar(1, d)], [scalar(2, d), scalar(3, d)], None]
    if kind in (1, 2, 3, 4):
        coefficient['axes'] = [1, 2]
    if kind == 2:
        coefficient['width'] = 2
    if kind == 3:
        coefficient.update(source_id=50, values=[2, 0, 2])
    if kind == 5:
        coefficient.update(axes=[1, 2], source_id=51, values=list(range(9)))
    return dict(field=d, id=11, layout=layout, order=order,
        output=dict(id=12, layout=[(1, 2)], point=[tuple(range(7, 7+d))], value=tuple(range(1234567, 1234567+d))),
        coefficient_id=13, inputs=[14, 15, 16], terms=[(tuple(range(9, 9+d)), [0, 1, 0]), (scalar(4, d), [])],
        coefficient=coefficient)


def rejects(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('malformed descriptor accepted')


def check():
    cases, prefixes = 0, 0
    for d in (4, 8):
        for kind in range(6):
            for order in (0, 1):
                for selected in (False, True):
                    s = fixture(d, kind, order, selected)
                    raw = encode(s)
                    assert decode(raw) == s and encode(decode(raw)) == raw
                    if kind == 3:
                        assert raw.endswith(struct.pack('<BBQQQQQ', 1, 2, 50, 3, 2, 0, 2))
                    if kind == 5:
                        assert raw.endswith(bytes([2, 1, 2])+struct.pack('<QQ9I', 51, 9, *range(9)))
                    rejects(lambda: decode(raw+b'\x00'))
                    # This fixed fixture gives independent header/count byte offsets.
                    for at, size in ((65+8*d, 4), (93+8*d, 4)):
                        rejects(lambda at=at, size=size: decode(raw[:at]+b'\xff'*size+raw[at+size:]))
                    for at, value in ((0, 2), (1, 2), (10, 255), (38, 2), (111+16*d, 6), (112+16*d, 2)):
                        rejects(lambda at=at, value=value: decode(raw[:at]+bytes([value])+raw[at+1:]))
                    if kind in (3, 5):
                        at = len(raw)-(24 if kind == 3 else 36)-8
                        rejects(lambda at=at: decode(raw[:at]+b'\xff'*8+raw[at+8:]))
                    for end in range(len(raw)):
                        rejects(lambda end=end: decode(raw[:end]))
                        prefixes += 1
                    needle = struct.pack('<'+'I'*d, *s['output']['value'])
                    assert raw.count(needle) == 1
                    at = raw.index(needle)
                    rejects(lambda: decode(raw[:at]+struct.pack('<I', P)+raw[at+4:]))
                    cases += 1
    # Independently assembled scalar statement: no hidden lengths/alignment.
    for d in (4, 8):
        s = fixture(d)
        s.update(id=1, layout=[(0, 1)], inputs=[], terms=[(scalar(1, d), [])], coefficient_id=2)
        s['output'] = dict(id=3, layout=[], point=[], value=scalar(1, d))
        s['coefficient']['selectors'] = [None]
        field = struct.pack('<'+'I'*d, *scalar(1, d))
        expected = (struct.pack('<BBQBBQBQB', 1, d, 1, 1, 0, 1, 0, 3, 0)
                    +field+struct.pack('<QII', 2, 0, 1)+field+b'\x00\x00\x00')
        assert encode(s) == expected and decode(expected) == s
    s = fixture(4)
    s['output'].update(id=s['inputs'][0], layout=s['layout'], point=[scalar(1, 4)]*5)
    assert decode(encode(s)) == s
    mutations = [lambda s: s.update(field=2), lambda s: s.update(order=2),
        lambda s: s['inputs'].append(s['inputs'][0]), lambda s: s.update(coefficient_id=s['inputs'][0]),
        lambda s: s['terms'].append((scalar(0, 4), [0]*4)),
        lambda s: s['terms'].append((scalar(1, 4), [3])),
        lambda s: s['layout'].__setitem__(0, (1, 3)),
        lambda s: s['output']['point'].append(scalar(1, 4)),
        lambda s: s['coefficient'].update(axes=[1]), lambda s: s.update(extra=1)]
    for change in mutations:
        s = fixture(4);change(s);rejects(lambda: encode(s))
    for kind, change in [(1, lambda c: c.update(axes=[1, 1])),
                         (2, lambda c: c.update(width=0)),
                         (3, lambda c: c.update(values=[3, 0, 0])),
                         (5, lambda c: c.update(values=[P]*9))]:
        s = fixture(4, kind);change(s['coefficient']);rejects(lambda: encode(s))
    print(f'{cases} both-field descriptors round-trip; {prefixes} truncated prefixes and malformed cases reject.')
    print('Canonical bytes only; no authenticated source, production consumer or NC credit.')


if __name__ == '__main__':
    check()
