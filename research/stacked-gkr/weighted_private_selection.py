"""RFC-0006 A4 / Q20: closed weighted descriptor; no private source authenticator."""
import struct
from private_selection import (GridSpec, Transcript, WEIGHTED, bounded, element,
                               need, pairs, _prove, _verify, sc)


def derive(meta, point, value, d):
    need(type(meta) is dict and len(meta) == 5 and set(meta) == {'layout', 'source_axes', 'category_axis', 'selectors', 'source_id'})
    axes, chosen, category = meta['layout'], meta['source_axes'], meta['category_axis']
    need(d in (4, 8) and type(axes) is tuple and 2 <= len(axes) <= 64)
    for axis in axes:
        need(type(axis) is tuple and len(axis) == 2)
        bits, real = axis
        need(type(bits) is int and type(real) is int and 0 <= bits <= 63 and 1 <= real <= 1 << bits)
    need(sum(b for b, _ in axes) <= 63 and len(point) == sum(b for b, _ in axes))
    need(type(chosen) is tuple and 1 <= len(chosen) < len(axes)
         and all(type(a) is int and 0 <= a < len(axes) for a in chosen)
         and all(left < right for left, right in zip(chosen, chosen[1:])))
    need(type(category) is int and 0 <= category < len(axes) and category not in chosen)
    source_id = meta['source_id']
    need(type(source_id) is int and 0 <= source_id < 1 << 64)
    selectors = meta['selectors']
    need(type(selectors) is tuple and len(selectors) == len(axes))
    raw = bytearray([1, d, len(axes)])
    raw.extend(b''.join(struct.pack('<BQ', *axis) for axis in axes))
    raw.extend(bytes([len(chosen), *chosen, category])+struct.pack('<Q', source_id))
    source_axis = [False]*len(axes)
    for axis in chosen:
        source_axis[axis] = True
    all_pairs, at = [], 0
    for (bits, _), selector in zip(axes, selectors):
        need(selector is None or type(selector) is tuple and len(selector) == bits)
        raw.append(selector is not None)
        if selector is not None:
            for z in selector:
                element(z, d)
                raw.extend(sc.encode(z))
        axis_point = point[at:at+bits]
        for q in axis_point:
            element(q, d)
        axis_pairs = pairs(axis_point, d)
        if selector is not None:
            axis_pairs = [(sc.mul(q[0], z[0]), sc.mul(q[1], z[1]))
                          for q, z in zip(axis_pairs, pairs(selector, d))]
        all_pairs.append(axis_pairs)
        at += bits
    element(value, d)
    raw.extend(b''.join(sc.encode(q) for q in [*point, value]))
    scale = sc.scalar(1, d)
    for axis, (_, real) in enumerate(axes):
        if not source_axis[axis] and axis != category:
            scale = sc.mul(scale, bounded(all_pairs[axis], real, d))
    spec = GridSpec(tuple(axes[a] for a in chosen), *axes[category])
    spec.validate()
    rows = [pair for a in chosen for pair in all_pairs[a]]
    return bytes(raw), spec, rows, all_pairs[category], scale, source_id


def prove(t, meta, point, value, indices):
    raw, spec, rows, columns, scale, _ = derive(meta, point, value, t.degree)
    return _prove(t, spec, rows, columns, scale, value, indices, WEIGHTED, raw)


def verify_reduction(t, meta, point, value, proof):
    raw, spec, rows, columns, scale, source_id = derive(meta, point, value, t.degree)
    receipt = _verify(t, spec, rows, columns, scale, value, proof, WEIGHTED, raw)
    receipt['source'] = (source_id, spec.axes, spec.category_bits, spec.categories)
    return receipt
