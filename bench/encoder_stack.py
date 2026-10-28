"""RFC-0010 A4/A5: inventory actual arm64 compiler frames, not process stack usage."""
import hashlib
from pathlib import Path
import re
import subprocess


def frame_bytes(code):
    """Propagate exact SP displacement through direct control flow; reject ambiguity."""
    by_address = {address: i for i, (address, _, _) in enumerate(code)}
    pending, seen, peak = [(0, 0)], {}, 0
    while pending:
        at, depth = pending.pop()
        if at in seen:
            assert seen[at] == depth, 'inconsistent or growing stack cycle'
            continue
        seen[at] = depth
        _, opcode, operands = code[at]
        if opcode in ('sub', 'add') and operands.startswith('sp, sp,'):
            m = re.fullmatch(r'sp, sp, #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(12))?', operands)
            assert m, (opcode, operands)
            change = int(m[1], 0) << (12 if m[2] else 0)
            depth += change if opcode == 'sub' else -change
        elif opcode in ('stp', 'str', 'ldp', 'ldr'):
            m = re.search(r'\[sp, #(-?(?:0x[0-9a-f]+|[0-9]+))\]!', operands)
            post = re.search(r'\[sp\], #(-?(?:0x[0-9a-f]+|[0-9]+))', operands)
            if m or post:
                depth -= int((m or post)[1], 0)
        elif opcode in ('mov', 'and', 'sub', 'add') and operands.startswith('sp,'):
            raise AssertionError((opcode, operands))
        assert depth >= 0, 'unmatched stack release'
        peak = max(peak, depth)
        if opcode == 'ret':
            assert depth == 0, 'return with retained frame'
            continue
        assert opcode != 'br', 'indirect branch requires separate analysis'
        branch = opcode == 'b' or opcode.startswith('b.') or opcode in ('cbz', 'cbnz', 'tbz', 'tbnz')
        if branch:
            target = operands.split(',')[-1].split(';')[0].strip()
            if target.startswith('0x') and int(target, 16) in by_address:
                pending.append((by_address[int(target, 16)], depth))
            else:
                assert opcode == 'b', 'unresolved conditional target'
        if opcode != 'b' and at+1 < len(code):
            pending.append((at+1, depth))
    return peak

def inspect(binary):
    binary = Path(binary)
    raw = subprocess.check_output(['otool', '-tvV', str(binary)])
    functions = {}
    current = None
    for line in raw.decode().splitlines():
        if line.startswith('__') and line.endswith(':'):
            current = line[:-1]
            functions[current] = []
        elif current and re.match(r'^[0-9a-f]{16}\t', line):
            parts = line.split('\t')
            functions[current].append((int(parts[0],16), parts[1], parts[2] if len(parts)>2 else ''))
    selected = {name: code for name, code in functions.items()
                if name.startswith('__ZN10stele_code') or name.startswith('__ZN6blake3')}
    assert selected and any('Execution' in name for name in selected)
    assert any('6blake34hash' in name for name in selected)
    records = []
    for name, code in selected.items():
        frame = frame_bytes(code)
        calls = {operands for _, opcode, operands in code if opcode in ('bl', 'blr')}
        records.append(dict(symbol=name, frame_bytes=frame, calls=sorted(calls)))
    return dict(
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        disassembly_sha256=hashlib.sha256(raw).hexdigest(),
        scope='Exact control-flow stack-pointer frame reservations for emitted stele-code/BLAKE3 symbols in '
              'this arm64 release binary. Inlined locals belong to their enclosing frame. '
              'This inventory is not measured live stack, a total call-chain/process bound '
              'or allocator/runtime/caller frames. Calls and recursive-frame counts remain '
              'explicit; process RSS includes the actual worker stack.',
        frames=records,
    )
