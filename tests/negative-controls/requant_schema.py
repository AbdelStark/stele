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


def scale(c, terms):
    return [(c*v, factors) for v, factors in terms]


def constant(value):
    return [(value, ())]


def product(left, right):
    return [(a*b, (*af, *bf)) for a, af in left for b, bf in right]


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

    def variable(self, row, power=1):
        return [(1, (5+row,)*power)]

    def digit(self, operand, k):
        if isinstance(operand, int):
            return constant((operand >> (8*k)) & 255)
        if operand == 'U':
            return [(1, (1+k,))] if k < 4 else constant(0)
        if operand in ('s', '2s'):
            return scale(2 if operand == '2s' else 1, self.variable(0)) if k == 0 else constant(0)
        rows = self.blocks[operand].rows
        return self.variable(rows[k]) if k < len(rows) else constant(0)

    def whole(self, block):
        return [term for k, row in enumerate(block.rows) for term in scale(256**k, self.variable(row))]

    def main_carry(self, role, k):
        carries = self.role_carries[role]
        return self.whole(carries[k-1]) if 1 <= k <= len(carries) else constant(0)

    def constraints(self):
        """RFC-0023 §2.2 ordered integer terms, before field embedding or batching."""
        out = []
        def real(name, terms):
            out.append((name, [(c, (0, *factors)) for c, factors in terms]))
        def boolean(name, row):
            real(name, self.variable(row, 2)+scale(-1, self.variable(row)))
        def cap(block):
            for k, row in enumerate(block.rows):
                terms = self.variable(row)+self.variable(block.slack[k])
                terms += constant(0) if k == 0 else self.variable(block.carry[k-1])
                terms += constant(-((block.cap >> (8*k)) & 255))
                terms += constant(0) if k == len(block.rows)-1 else scale(-256, self.variable(block.carry[k]))
                real(f'{block.name}.cap.column[{k}]', terms)
            for k, row in enumerate(block.carry):
                boolean(f'{block.name}.cap.Boolean[{k}]', row)
        boolean('sign.Boolean', 0)
        for name in self.values:
            cap(self.blocks[name])
        c = self.static
        pairs = dict(input_lhs=[('U',1), ('v','2s')], input_rhs=[(1 << 31,1), ('v',1)],
                     product=[('v',self.spec.mantissa)], bias=[('a',1), (c['bias'],1)],
                     quotient_product=[('q',c['divisor'])], division=[('qd',1), ('r0',1)])
        def operand_cap(value):
            if isinstance(value, int):
                return value
            if value == 'U':
                return (1 << 32)-1
            if value == '2s':
                return 2
            return self.blocks[value].cap
        for role, record in c['columns'].items():
            for left, right in pairs[role]:
                assert operand_cap(left) <= record['left_max']
                assert operand_cap(right) <= record['right_max']
            if role in self.result_caps:
                cap(self.result_caps[role])
            for block in self.role_carries[role]:
                cap(block)
            for k in range(len(record['result_caps'])):
                terms = []
                for left, right in pairs[role]:
                    for i in range(len(record['left_caps'])):
                        j = k-i
                        if 0 <= j < len(record['right_caps']):
                            terms += product(self.digit(left, i), self.digit(right, j))
                terms += self.main_carry(role, k)
                terms += scale(-1, self.digit(self.targets[role], k))
                terms += scale(-256, self.main_carry(role, k+1))
                real(f'{role}.column[{k}]', terms)
        for k in range(4):
            terms = self.digit('u', k)+self.digit('s', k)
            terms += constant(0) if k == 0 else self.variable(self.u_carries[k-1])
            terms += scale(-1, self.digit('v', k))
            terms += constant(0) if k == 3 else scale(-256, self.variable(self.u_carries[k]))
            real(f'u-add.column[{k}]', terms)
        for k, row in enumerate(self.u_carries):
            boolean(f'u-add.Boolean[{k}]', row)
        real('target', self.whole(self.blocks['q'])+self.whole(self.blocks['z0'])
             +constant(-(c['output_max']-1))+scale(-1, self.variable(0)))
        for row in range(4):
            out.append((f'input.padding[{row}]', [(1,(1+row,)), (-1,(0,1+row))]))
        for row in range(self.L):
            out.append((f'advice.padding[{row}]', [(1,(5+row,)), (-1,(0,5+row))]))
        for row in range(self.L, self.R):
            out.append((f'advice.zero[{row}]', self.variable(row)))
        return out

    def witness(self, accumulator):
        """Independent scalar row for direct equation tests, not a proof verifier."""
        w = MODULES['requant'].witness(self.spec, accumulator)
        c, advice = self.static, [0]*self.R
        def put(rows, value):
            assert 0 <= value < 256**len(rows)
            for k, row in enumerate(rows):
                advice[row] = (value >> (8*k)) & 255
        v, sign = w['magnitude'], w['sign']
        values = dict(v=v, a=w['product'], q=w['quotient'], qd=w['scaled_quotient'],
                      r0=w['remainder'], t=w['product']+c['bias'], w0=(1 << 31)+v,
                      u=v-sign, z0=c['output_max']-1+sign-w['quotient'])
        advice[0] = sign
        for role, blocks in self.role_carries.items():
            for k, block in enumerate(blocks, 1):
                values[block.name] = w['columns'][role]['carry'][k]
        caps = list(self.blocks.items())+[(self.targets[role], block) for role, block in self.result_caps.items()]
        for name, block in caps:
            value = values[name]
            assert 0 <= value <= block.cap
            put(block.rows, value)
            put(block.slack, block.cap-value)
            carry = 0
            for k, row in enumerate(block.rows):
                carry = (advice[row]+advice[block.slack[k]]+carry)//256
                if k < len(block.carry):
                    advice[block.carry[k]] = carry
            assert carry == 0
        carry = 0
        for k in range(4):
            carry = (advice[self.blocks['u'].rows[k]]+(sign if k == 0 else 0)+carry)//256
            if k < 3:
                advice[self.u_carries[k]] = carry
        assert carry == 0
        offset = accumulator+(1 << 31)
        return [1]+[(offset >> (8*k)) & 255 for k in range(4)]+advice

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


def cases():
    rng = random.Random(0x2301)
    cases = [(1,0,8), (65535,32,16), (1,62,16), (1,1,8), (1,2,8),
             (255,7,16), (256,8,8), (65535,62,8), (65535,0,8), (65535,0,16)]
    cases += [(rng.randint(1,65535), rng.randrange(63), rng.choice((8,16))) for _ in range(8)]
    return cases


def source_header():
    sources = [Path(m.__file__) for m in MODULES.values()] + [Path(__file__)]
    return [f'# {p.relative_to(ROOT)} {hashlib.sha256(p.read_bytes()).hexdigest()}' for p in sources]


def fixtures():
    lines = source_header()
    for params in cases():
        schema = Schema(*params)
        lines += [' '.join(map(str, params)), schema.bound_bytes.hex(), schema.description()]
    return '\n'.join(lines)+'\n'


def constraint_fixtures():
    """Test grammar: parameters; complete terms; honest rows; named-equation mutations.

    Coefficients are canonical M31 words. Native tests embed them in both full
    extension encodings and check every higher limb, avoiding duplicate fixtures.
    """
    from math import prod
    prime = (1 << 31)-1
    lines = source_header()
    for params in cases():
        schema = Schema(*params)
        equations = schema.constraints()
        terms = [len(equations)]
        for _, equation in equations:
            terms += [max(len(f) for _, f in equation), len(equation)]
            for c, factors in equation:
                terms += [c % prime, len(factors), *factors]
        candidates = [0,-1,1]
        if params == (1,0,8): candidates += [-128,127]
        if params == (1,1,8): candidates += [-3,3]
        if params in ((65535,32,16),(1,62,16)): candidates += [-(1 << 31),(1 << 31)-1]
        rows, inputs = [], []
        for acc in candidates:
            try:
                row = schema.witness(acc)
            except ValueError as error:
                assert str(error) == 'OutputRange'
            else:
                rows.append(row); inputs.append(acc)
        mutations = []
        names = [name for name, _ in equations]
        def mutate(witness, ordinal, value, name):
            row = ([0]*(5+schema.R)) if witness == -1 else rows[witness].copy()
            assert row[ordinal] != value
            row[ordinal] = value
            at = names.index(name)
            result = sum(c*prod(row[f] for f in factors) for c, factors in equations[at][1]) % prime
            mutations.extend((witness, ordinal, value, at, result))
        if params in ((1,0,8),(65535,32,16),(1,62,16)):
            mutate(-1,1,1,'input.padding[0]')
            mutate(-1,5,1,'advice.padding[0]')
            mutate(-1,5+schema.L,1,f'advice.zero[{schema.L}]')
            mutate(0,5+schema.L,1,f'advice.zero[{schema.L}]')
        if params == (1,0,8):
            one = inputs.index(1)
            for ordinal,value,name in [(1,0,'input_lhs.column[0]'),
                (5+schema.blocks['w0'].rows[0],2,'input_rhs.column[0]'),
                (5+schema.blocks['v'].carry[0],2,'v.cap.Boolean[0]'),
                (5+schema.role_carries['product'][0].rows[0],1,'product.column[0]'),
                (5+schema.u_carries[0],2,'u-add.Boolean[0]'),
                (5+schema.blocks['q'].rows[0],128,'target')]:
                mutate(one,ordinal,value,name)
            mutate(0,5,1,'u-add.column[0]')
            for name in ('division.column[0]','division.column[1]','division.result.cap.column[2]'):
                mutate(one,5+schema.blocks['t'].rows[2],1,name)
        lines += [' '.join(map(str, (*params,5+schema.R))), ' '.join(map(str,terms)),
                  ' '.join(map(str,[len(rows),*(v for row in rows for v in row)])),
                  ' '.join(map(str,[len(mutations)//5,*mutations]))]
    return '\n'.join(lines)+'\n'
