"""Q28 candidate row codec; no private decomposition proof or PCS admission."""
WORD_BITS = 30
MASK = (1 << WORD_BITS)-1


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def shape(width, count, columns, max_words):
    require(type(width) is int and width in (8, 16), 'Width')
    require(type(count) is int and count > 0, 'Shape')
    require(type(columns) is int and columns > 0 and columns & (columns-1) == 0, 'Shape')
    require(type(max_words) is int and max_words >= 0, 'Capacity')
    used = (count*width+WORD_BITS-1)//WORD_BITS
    require(used <= columns, 'Shape')
    require(columns <= max_words, 'Capacity')
    return used


def pack(values, width, columns, max_words):
    require(type(values) in (tuple, list), 'Shape')
    shape(width, len(values), columns, max_words)
    require(all(type(x) is int and -(1 << (width-1)) <= x < 1 << (width-1)
                for x in values), 'SourceRange')
    output = []
    bits = buffer = 0
    for value in values:
        buffer |= (value & ((1 << width)-1)) << bits
        bits += width
        while bits >= WORD_BITS:
            output.append(buffer & MASK)
            buffer >>= WORD_BITS
            bits -= WORD_BITS
    if bits:
        output.append(buffer)
    output.extend([0]*(columns-len(output)))
    return tuple(output)


def unpack(words, width, count, columns, max_words):
    require(type(words) in (tuple, list), 'Shape')
    used = shape(width, count, columns, max_words)
    require(len(words) == columns, 'Shape')
    require(all(type(x) is int and 0 <= x <= MASK for x in words), 'PackedRange')
    remaining = count*width % WORD_BITS
    require(not remaining or words[used-1] >> remaining == 0, 'Tail')
    require(not any(words[used:]), 'Padding')
    output = []
    bits = buffer = at = 0
    for _ in range(count):
        while bits < width:
            buffer |= words[at] << bits
            bits += WORD_BITS
            at += 1
        raw = buffer & ((1 << width)-1)
        output.append(raw-(1 << width) if raw >> (width-1) else raw)
        buffer >>= width
        bits -= width
    return tuple(output)
