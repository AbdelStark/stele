"""RFC-0010 A1 v2 row regeneration and fixed logical workspace; research only."""
import struct
from identity import parameters, validate_row, require
from sampler import parse_manifest, block, neighbors, coefficients
from recursive import geometry, circle, sc


def requirements(raw_id, field, address_bits, selected=0):
    info = parameters(raw_id, field)
    require(info['family'] == 'expander-m31/v2', 'InvalidCodeId')
    require(type(address_bits) is int and address_bits in (32,64), 'Capacity')
    require(type(selected) is int and 0 <= selected <= (1 << 64)-1, 'Capacity')
    _, j = parse_manifest(raw_id)
    n, width = info['message_len'], 4*field
    scratch = (n-64)//3
    rows = sum(r for k in range(4,j+1) for r,_,_ in geometry(k))
    # Requested vector payloads only; stack, allocator rounding and RSS are separate.
    owned = (2*n+scratch+128+selected)*width+127*4+21*(address_bits//8)
    query_input = selected*(address_bits//8)
    require(max(n*width, query_input, owned) <= (1 << (address_bits-1))-1, 'Capacity')
    # Operation counters are u64, not address-sized buffer lengths.
    require(max(64*rows, info['edge_count']*field) <= (1 << 64)-1, 'Capacity')
    return dict(input_bytes=n*width, query_input_bytes=query_input,
                owned_payload_bytes=owned, scratch_slots=scratch,
                rows=rows, edges=info['edge_count'], hash_blocks_upper=64*rows)


def zeros(length, degree):
    return [sc.scalar(0,degree)]*length


def encode(raw_id, field, row):
    info = parameters(raw_id, field)
    require(info['family'] == 'expander-m31/v2', 'InvalidCodeId')
    validate_row(info, row)
    plan = requirements(raw_id, field, 64)
    seed, exponent = parse_manifest(raw_id)
    n = info['message_len']
    output, scratch = zeros(2*n,field), zeros(plan['scratch_slots'],field)
    count = dict(hash_blocks=0, sparse_edges=0, sparse_limb_adds=0,
                 sparse_limb_muls=0, scratch_peak=0, base_component_encodes=0)

    def words(level, kind, r, stream):
        for counter in range(32):
            raw = block(seed,level,kind,r,stream,counter)
            count['hash_blocks'] += 1
            yield from struct.unpack('<8I',raw)

    def scatter(level, kind, source, start, target, offset):
        rows, columns, degree = geometry(level)[kind]
        for r in range(rows):
            chosen = neighbors(words(level,kind,r,0), columns, degree)
            entries = coefficients(words(level,kind,r,1), degree)
            value = source[start+r]
            for column, coefficient in zip(chosen, entries):
                at = offset+column
                target[at] = sc.add(target[at], tuple(x*coefficient % sc.P for x in value))
                count['sparse_edges'] += 1
                count['sparse_limb_adds'] += field
                count['sparse_limb_muls'] += field

    def run(j, source, start, out, work):
        if j == 3:
            # Native proposal calls existing Circle::encode; its 128-value overlap is charged.
            base = list(zip(*(circle.encode([source[start+i][k] for i in range(64)],1)
                              for k in range(field))))
            for i, value in enumerate(base):
                output[out+i] = value
            count['base_component_encodes'] += field
            return
        size = 4**j
        for i in range(size):
            output[out+i] = source[start+i]
        count['scratch_peak'] = max(count['scratch_peak'],work+size//4)
        scatter(j,0,source,start,scratch,work)
        run(j-1,scratch,work,out+size,work+size//4)
        scatter(j,1,output,out+size,output,out+3*size//2)

    run(exponent,row,0,0,0)
    return output, count


def eval_row(raw_id, field, row, columns):
    info = parameters(raw_id, field)
    require(info['family'] == 'expander-m31/v2', 'InvalidCodeId')
    validate_row(info, row)
    require(type(columns) in (list,tuple) and all(type(c) is int and 0 <= c < info['codeword_len']
                                               for c in columns), 'Column')
    if not columns:
        return []
    requirements(raw_id,field,64,len(columns))
    selected = zeros(len(columns),field)
    word, _ = encode(raw_id,field,row)
    for i, column in enumerate(columns):
        selected[i] = word[column]
    return selected
