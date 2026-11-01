"""RFC-0023 §2.1 independent static layout; no witness or proof admission."""
from dataclasses import dataclass
import hashlib
import importlib
from pathlib import Path
import random
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'research/cqis-bounds'))
MODULES = {name: importlib.import_module(name)
           for name in ('limbs', 'requant', 'norm_bounds', 'encoding')}
for name, module in MODULES.items():
    assert Path(module.__file__).resolve() == ROOT/f'research/cqis-bounds/{name}.py'


def width(cap):
    return max(1, (cap.bit_length()+7)//8)


@dataclass
class Block:
    name: str
    cap: int
    rows: list
    slack: list
    carry: list


class Schema:
    def __init__(self, mantissa, shift, bits):
        self.spec = MODULES['requant'].Spec(mantissa, shift, bits)
        c = self.static = MODULES['requant'].derive(self.spec)
        self.bound_bytes = MODULES['encoding'].encode(self.spec)
        self.names, self.blocks, self.role_carries, self.result_caps = ['s'], {}, {}, {}
        caps = [('v', 1 << 31), ('a', c['product_max']), ('q', c['quotient_max']),
                ('qd', c['quotient_max']*c['divisor']), ('r0', c['divisor']-1),
                ('t', c['product_max']+c['bias']), ('w0', 1 << 32),
                ('u', 1 << 31), ('z0', c['output_max'])]
        self.values = [name for name, _ in caps]
        for name, cap in caps:
            self.blocks[name] = Block(name, cap, self.allocate(name, width(cap)), [], [])
        for name in self.values:
            self.cap_allocate(self.blocks[name])
        self.targets = dict(input_lhs='w0', input_rhs='w0', product='a', bias='t',
                            quotient_product='qd', division='t')
        for role, record in c['columns'].items():
            target = self.blocks[self.targets[role]]
            if target.cap > record['result_max']:
                block = Block(role+'.result', record['result_max'], target.rows, [], [])
                self.cap_allocate(block)
                self.result_caps[role] = block
            carries = []
            for k, cap in enumerate(record['carry_caps'][1:-1], 1):
                name = f'{role}.c{k}'
                block = Block(name, cap, self.allocate(name, width(cap)), [], [])
                self.blocks[name] = block
                self.cap_allocate(block)
                carries.append(block)
            self.role_carries[role] = carries
        self.u_carries = self.allocate('u-add-carry', 3)
        self.L = len(self.names)
        self.a0 = (self.L-1).bit_length()
        self.R = 1 << self.a0
        assert self.L < 2048
        self.names += [f'zero[{k}]' for k in range(self.L, self.R)]

    def allocate(self, name, count):
        start = len(self.names)
        self.names += [f'{name}[{k}]' for k in range(count)]
        return list(range(start, start+count))

    def cap_allocate(self, block):
        block.slack = self.allocate(block.name+'.slack', len(block.rows))
        block.carry = self.allocate(block.name+'.cap-carry', len(block.rows)-1)

    def description(self):
        """Test-only integer sequence, not a protocol encoding."""
        out = [self.L, self.R, *self.u_carries]
        def block(b):
            out.append(b.cap)
            for rows in (b.rows, b.slack, b.carry):
                out.extend((len(rows), *rows))
        for name in self.values:
            block(self.blocks[name])
        for name, role in self.static['columns'].items():
            out.extend(role[k] for k in ('count', 'left_max', 'right_max', 'result_max'))
            out.extend(len(role[k]) for k in ('left_caps', 'right_caps', 'result_caps'))
            out.append(int(name in self.result_caps))
            if name in self.result_caps:
                block(self.result_caps[name])
            out.append(len(self.role_carries[name]))
            for carry in self.role_carries[name]:
                block(carry)
        return ' '.join(map(str, out))


def fixtures():
    rng = random.Random(0x2301)
    cases = [(1,0,8), (65535,32,16), (1,62,16), (1,1,8), (1,2,8),
             (255,7,16), (256,8,8), (65535,62,8), (65535,0,8), (65535,0,16)]
    cases += [(rng.randint(1,65535), rng.randrange(63), rng.choice((8,16))) for _ in range(8)]
    sources = [Path(m.__file__) for m in MODULES.values()] + [Path(__file__)]
    lines = [f'# {p.relative_to(ROOT)} {hashlib.sha256(p.read_bytes()).hexdigest()}' for p in sources]
    for params in cases:
        schema = Schema(*params)
        lines += [' '.join(map(str, params)), schema.bound_bytes.hex(), schema.description()]
    return '\n'.join(lines)+'\n'
