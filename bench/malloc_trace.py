"""Reconstruct simultaneous live malloc requests from a macOS allEvents trace.

MallocStackLoggingNoCompact must be enabled from worker startup. Markers are
real allocations retained until the worker pauses for inspection. This measures
requested heap payload, including harness allocations; allocator metadata,
unlogged profiler internals and stacks are outside it. Process RSS is separate.
No protocol acceptance or benchmark qualification follows from this parser.
"""
import gzip
import re


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def events(path):
    """Keep allocator order and fail on an unrecognized allocation event."""
    allocation = re.compile(r'ALLOC (0x[0-9a-f]+)-(0x[0-9a-f]+) \[size=(\d+)\]:')
    release = re.compile(r'FREE +(0x[0-9a-f]+):')
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt') as source:
        for line_number, line in enumerate(source, 1):
            if match := allocation.match(line):
                address, end, size = int(match[1], 16), int(match[2], 16), int(match[3])
                require(end-address+1 == size, f'Allocation extent at line {line_number}')
                yield line_number, address, size
            elif match := release.match(line):
                yield line_number, int(match[1], 16), None
            elif line.startswith(('VM_ALLOC ', 'VM_DEALLOC ')):
                # Anonymous VM is a separate scope; it is not a Rust Vec capacity.
                continue
            elif line.startswith(('ALLOC ', 'FREE ')) or re.match(r'^[A-Z_]+\s+0x', line):
                raise ValueError(f'Unknown memory event at line {line_number}')


def summarize(path, markers):
    """Observe peaks across ordered live sets, never add independent maxima."""
    require(bool(markers), 'Missing markers')
    require(len({m['name'] for m in markers}) == len(markers), 'Duplicate marker name')
    addresses = [int(m['address'], 16) for m in markers]
    require(len(set(addresses)) == len(markers), 'Duplicate marker address')
    live, current, peak, allocations, releases = {}, 0, 0, 0, 0
    for line, address, size in events(path):
        if size is None:
            require(address in live, f'Free without allocation at line {line}')
            current -= live.pop(address)[0]
            releases += 1
        else:
            require(address not in live, f'Overlapping allocation at line {line}')
            live[address] = (size, line)
            current += size
            peak = max(peak, current)
            allocations += 1
    marker_lines = []
    for marker, address in zip(markers, addresses, strict=True):
        require(address in live and live[address][0] == marker['bytes'],
                f'Marker not retained with its declared capacity: {marker["name"]}')
        marker_lines.append(live[address][1])
    require(marker_lines == sorted(set(marker_lines)), 'Unordered markers')

    # Final live addresses identify markers even if startup reused those addresses.
    selected = dict(zip(marker_lines, markers, strict=True))
    live, current, active, stages = {}, 0, None, []
    for line, address, size in events(path):
        if size is None:
            current -= live.pop(address)
        else:
            live[address] = size
            current += size
        if active is not None:
            active['peak_heap_requested_bytes'] = max(active['peak_heap_requested_bytes'], current)
        if line in selected:
            if active is not None:
                active['end_heap_requested_bytes'] = current
                active['end_marker'] = selected[line]['name']
                stages.append(active)
            active = dict(start_marker=selected[line]['name'],
                          start_heap_requested_bytes=current, peak_heap_requested_bytes=current)
    return dict(scope='observed malloc request payload; includes live caller and harness buffers; '
                'excludes allocator metadata, unlogged profiler internals, anonymous VM and stacks',
                allocations=allocations, frees=releases, heap_requested_live_bytes=current,
                heap_requested_peak_bytes=peak, stages=stages)
