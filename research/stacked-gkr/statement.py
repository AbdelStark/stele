"""Q20 candidate byte codec, not an Accepted core protocol or source authenticator."""
import math

P = 2**31-1


def need(condition):
    if not condition:
        raise ValueError('InvalidStacked')


def uint(value, bits):
    need(type(value) is int and 0 <= value < 1 << bits)
    return value.to_bytes(bits//8, 'little')


def layout(axes, required=False):
    need((1 if required else 0) <= len(axes) <= 64)
    for bits, real in axes:
        need(type(bits) is int and 0 <= bits <= 63)
        need(type(real) is int and 1 <= real <= 1 << bits)
    need(sum(bits for bits, _ in axes) <= 63)
    return uint(len(axes), 8)+b''.join(uint(b, 8)+uint(n, 64) for b, n in axes)


def field(value, d):
    need(len(value) == d and all(type(x) is int and 0 <= x < P for x in value))
    return b''.join(uint(x, 32) for x in value)


def encode(s):
    need(set(s) == {'field','id','layout','order','output','coefficient_id','inputs','terms','coefficient'})
    d, axes, o, c = s['field'], s['layout'], s['output'], s['coefficient']
    need(d in (4, 8) and type(d) is int and s['order'] in (0, 1) and type(s['order']) is int)
    need(set(o) == {'id','layout','point','value'})
    need(set(c) == {'kind','selectors','axes','source_id','values','width'})
    out = uint(1, 8)+uint(d, 8)+uint(s['id'], 64)+layout(axes, True)+uint(s['order'], 8)
    out += uint(o['id'], 64)+layout(o['layout'])
    need(len(o['point']) == sum(b for b, _ in o['layout']))
    out += b''.join(field(v, d) for v in o['point'])+field(o['value'], d)
    ids = s['inputs']
    for identity in [o['id'], s['coefficient_id'], *ids]:
        uint(identity, 64)
    need(len(set(ids)) == len(ids) and s['coefficient_id'] not in [o['id'], *ids])
    if o['id'] in ids:
        need(o['layout'] == axes)
    out += uint(s['coefficient_id'], 64)+uint(len(ids), 32)+b''.join(uint(i, 64) for i in ids)
    out += uint(len(s['terms']), 32)
    for coefficient, factors in s['terms']:
        need(len(factors) <= 3 and all(type(i) is int and 0 <= i < len(ids) for i in factors))
        out += field(coefficient, d)+uint(len(factors), 8)+b''.join(uint(i, 32) for i in factors)
    kind = c['kind']
    need(type(kind) is int and 0 <= kind <= 5 and len(c['selectors']) == len(axes))
    out += uint(kind, 8)
    for selector, (bits, _) in zip(c['selectors'], axes):
        out += uint(int(selector is not None), 8)
        if selector is not None:
            need(len(selector) == bits)
            out += b''.join(field(v, d) for v in selector)
    chosen = c['axes']
    need(all(type(i) is int and 0 <= i < len(axes) for i in chosen))
    need(len(set(chosen)) == len(chosen))
    need(c['width'] is None if kind != 2 else type(c['width']) is int and 0 < c['width'] < 1 << 64)
    if kind == 0:
        need(chosen == [])
    elif kind in (1, 2, 3, 4):
        need(len(chosen) == 2)
        out += b''.join(uint(i, 8) for i in chosen)
        a, b = (axes[i] for i in chosen)
        if kind in (1, 2):
            need(a[0] == b[0])
        if kind == 2:
            out += uint(c['width'], 64)
        if kind == 4:
            need(a[1] % b[1] == 0)
    else:
        need(chosen and chosen == sorted(chosen))
        out += uint(len(chosen), 8)+b''.join(uint(i, 8) for i in chosen)
    if kind in (3, 5):
        uint(c['source_id'], 64)
        need(c['source_id'] != s['coefficient_id'])
        source_layout = [axes[chosen[0]]] if kind == 3 else [axes[i] for i in chosen]
        if c['source_id'] in ids:
            need(source_layout == axes)
        if c['source_id'] == o['id']:
            need(source_layout == o['layout'])
        count = axes[chosen[0]][1] if kind == 3 else math.prod(axes[i][1] for i in chosen)
        need(len(c['values']) == count)
        bound = axes[chosen[1]][1] if kind == 3 else P
        need(all(type(v) is int and 0 <= v < bound for v in c['values']))
        out += uint(c['source_id'], 64)+uint(count, 64)
        out += b''.join(uint(v, 64 if kind == 3 else 32) for v in c['values'])
    else:
        need(c['source_id'] is None and c['values'] == [])
    return out


class Reader:
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def number(self, size):
        need(size <= len(self.raw)-self.at)
        value = int.from_bytes(self.raw[self.at:self.at+size], 'little')
        self.at += size
        return value

    def many(self, count, minimum, read):
        need(count <= (len(self.raw)-self.at)//minimum)
        return [read() for _ in range(count)]

    def field(self, d):
        value = tuple(self.many(d, 4, lambda: self.number(4)))
        need(all(x < P for x in value))
        return value

    def layout(self, required=False):
        count = self.number(1)
        need((1 if required else 0) <= count <= 64)
        axes = self.many(count, 9, lambda: (self.number(1), self.number(8)))
        layout(axes, required)
        return axes


def decode(raw):
    r = Reader(raw)
    need(r.number(1) == 1)
    d = r.number(1)
    need(d in (4, 8))
    s = dict(field=d, id=r.number(8), layout=r.layout(True), order=r.number(1))
    o = dict(id=r.number(8), layout=r.layout())
    o['point'] = r.many(sum(b for b, _ in o['layout']), 4*d, lambda: r.field(d))
    o['value'] = r.field(d)
    s.update(output=o, coefficient_id=r.number(8))
    s['inputs'] = r.many(r.number(4), 8, lambda: r.number(8))
    def term():
        value = r.field(d)
        count = r.number(1)
        need(count <= 3)
        return value, r.many(count, 4, lambda: r.number(4))
    s['terms'] = r.many(r.number(4), 4*d+1, term)
    kind = r.number(1)
    need(kind <= 5)
    c = dict(kind=kind, selectors=[], axes=[], source_id=None, values=[], width=None)
    for bits, _ in s['layout']:
        flag = r.number(1)
        need(flag in (0, 1))
        c['selectors'].append(None if flag == 0 else r.many(bits, 4*d, lambda: r.field(d)))
    if kind in (1, 2, 3, 4):
        c['axes'] = r.many(2, 1, lambda: r.number(1))
        if kind == 2:
            c['width'] = r.number(8)
    elif kind == 5:
        c['axes'] = r.many(r.number(1), 1, lambda: r.number(1))
    if kind in (3, 5):
        c['source_id'] = r.number(8)
        size = 8 if kind == 3 else 4
        c['values'] = r.many(r.number(8), size, lambda: r.number(size))
    s['coefficient'] = c
    need(r.at == len(raw))
    need(encode(s) == raw)
    return s
