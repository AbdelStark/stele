"""RFC-0023 §2.1 independent static layout; no witness or proof admission."""
from dataclasses import dataclass
import hashlib
import importlib
from pathlib import Path
import random
import struct
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


def codec_wire(degree, m, rows, q, repetitions, advice_blowup, input_blowup, counts):
    """RFC-0023 §2.4 canonical shape, NOT an authenticated proof.

    Sparse byte program: length, then (offset, nonzero byte) pairs; rest is zero.
    Mutations: (operation, offset, cause); operations are zero byte, p limb,
    truncate, append, other supported field tag. Causes: 0 pass, 1 outer shape, 2 outer scalar, 3/4 A9
    shape/row, 5 A5 shape/piece, 6 fraction scalar, 7/8 A5's A9 shape/row.
    Expected single-change decisions follow these independently typed regions;
    opaque response columns deliberately remain outside canonical-field checks.
    """
    size, writes, mutations = 0, [], []
    w = 4*degree
    def reserve(length):
        nonlocal size
        at = size; size += length
        return at
    def header(values, cause):
        for value in values:
            at = reserve(1)
            writes.extend((at,value))
            mutations.extend((0,at,cause))
            if value == degree:
                mutations.extend((4,at,cause))
    def scalars(length, cause):
        at = reserve(length)
        for offset in sorted({at,at+length-4}):
            mutations.extend((1,offset,cause))
    def packet(source_m, source_rows, blowup, certificate, nested):
        header([1],7 if nested else 3)
        scalars(w*(1 << source_m),8 if nested else 4)
        queries = counts(source_m,blowup)[0 if certificate else 1]
        at = reserve(queries*(4*source_rows+32*(source_m+blowup)))
        mutations.extend((1,at,0))  # unauthenticated response column, not its row
    def lookup(source_rows, blowup):
        header([1,degree],5)
        mu_m = 8+(degree.bit_length()-1)
        for _ in range(repetitions):
            reserve(32)
            packet(mu_m,1,1,True,True)
        depth = m+source_rows.bit_length()-1
        for _ in range(repetitions):
            for variables in (depth,8):
                scalars(w*(2+2*variables*variables+3*variables),6)
            scalars(w*(4*depth+3),6)
            packet(m,source_rows,blowup,False,True)
            scalars(w,5)  # ell=0: one complete range_8 multiplicity piece
            packet(mu_m,1,1,False,True)
    header([1,degree],1)
    reserve(32)
    packet(m,rows,advice_blowup,True,False)
    lookup(4,input_blowup)
    lookup(rows,advice_blowup)
    scalars(w*(4*m+5+rows),2)
    packet(m,4,input_blowup,False,False)
    packet(m,rows,advice_blowup,False,False)
    scalars(w*(4*m+2+q),2)
    packet(m,rows,advice_blowup,False,False)
    mutations.extend((2,0,1,3,0,1))
    assert all(0 <= at < size for at in writes[::2])
    return ' '.join(map(str,[size,*writes])), ' '.join(map(str,mutations))


def codec_fixtures():
    """Complete expected frames. The 274 source/identity bytes are caller inputs.

    Native tests substitute their genuine handles in that one explicit region;
    every other byte, including all ordered terms, is independently generated.
    """
    sys.path.insert(0, str(ROOT/'research/merkle-oracle'))
    policy = importlib.import_module('native_policy')
    path = Path(policy.__file__).resolve()
    assert path == ROOT/'research/merkle-oracle/native_policy.py'
    lines = source_header()+[f'# {path.relative_to(ROOT)} {hashlib.sha256(path.read_bytes()).hexdigest()}']
    cases = [(1,1,1,0,8,1,1,2), ((1 << 20)-1,3,65535,32,16,2,2,1),
             (7,2,1,62,16,1,1,1), (2,3,1,2,8,2,1,2)]
    for degree in (4,8):
        def scalar(v):
            return struct.pack('<I', v % ((1 << 31)-1))+bytes(4*(degree-1))
        def term(c, factors):
            return scalar(c)+bytes([len(factors)])+b''.join(struct.pack('<I', f) for f in factors)
        for stage,n,mantissa,shift,bits,r,ab,ib in cases:
            schema = Schema(mantissa,shift,bits)
            m, s = (n-1).bit_length(), stage << 40
            point = [struct.pack('<'+'I'*degree, *(11*(i+1)+j for j in range(degree))) for i in range(m)]
            value = struct.pack('<'+'I'*degree, *(101+j for j in range(degree)))
            statement = struct.pack('<BBIQBHBBBBH',1,degree,stage,n,m,mantissa,shift,bits,r,ab,len(schema.bound_bytes))
            statement += schema.bound_bytes+bytes(274)+b''.join(point)+value
            assert len(statement) == 297+len(schema.bound_bytes)+(m+1)*4*degree
            ids = [s+(1 << 28)]+[s+(1 << 24)+i for i in range(4+schema.R)]
            equations = schema.constraints()
            constraints = struct.pack('<IBI',stage,m,len(ids))+b''.join(struct.pack('<Q',i) for i in ids)+struct.pack('<I',len(equations))
            for i, (_, terms) in enumerate(equations):
                constraints += struct.pack('<QBI',s+4096+i,max(len(f) for _,f in terms),len(terms))
                constraints += b''.join(term(c,f) for c,f in terms)
            q = schema.blocks['q'].rows
            output_ids = [s+(1 << 28)+1,s+(1 << 24)+4]+[s+(1 << 24)+4+i for i in q]
            output = struct.pack('<BBQIBII',1,degree,s+2048,m,3,len(output_ids),2*len(q))
            output += b''.join(struct.pack('<Q',i) for i in output_ids)
            output += b''.join(term(c,f) for k in range(len(q)) for c,f in
                               [(256**k,(0,2+k)),(-2*256**k,(0,1,2+k))])+value
            # Independent OUTER costs; native tests add unchanged actual A5 totals.
            w, N, R, P = 4*degree, 1 << m, schema.R, len(ids)
            def opening(rows, blowup):
                cert, opens = policy.counts(m,blowup)
                response = 4*rows+32*(m+blowup)
                packet = 1+w*N+opens*response
                return (1+w*N+cert*response, packet,
                        145+w*(rows+N+1)+packet-1, opens*(1+m+blowup))
            ui, ai = opening(4,ib), opening(R,ab)
            flat_terms = [(c,f) for _,terms in equations for c,f in terms]
            zero_frame = struct.pack('<BBQIBBII',1,degree,s+1024,m,0,3,P,len(flat_terms))
            zero_frame += b''.join(struct.pack('<Q',i) for i in ids)+b''.join(term(c,f) for c,f in flat_terms)
            rounds = m*len(struct.pack('<QI',0,0)+bytes(4*w))
            zero_final = len(struct.pack('<QII',s+1024,P,1)+bytes(P*w))
            output_final = len(struct.pack('<QI',s+2048,len(output_ids))+bytes(len(output_ids)*w))
            groups = sum(len(struct.pack('<IB',stage,g)+bytes(137)+struct.pack('<IB',c,m)
                             +bytes(m*w)+bytes(c*(12+w))) for g,c in enumerate((4,R,1+len(q))))
            public = len(statement)+len(constraints)+len(zero_frame)+len(output)+2*rounds+zero_final+output_final+groups+ui[2]+2*ai[2]
            proof = 34+ai[0]+w*(8*m+P+len(output_ids))+ui[1]+2*ai[1]
            sizes = ((4+R)*N,proof,public,1+ui[3]+2*ai[3])
            lines += [' '.join(map(str,(degree,stage,n,mantissa,shift,bits,r,ab,ib))),
                      statement.hex(),constraints.hex(),output.hex(),' '.join(map(str,sizes))]
            lines += codec_wire(degree,m,R,len(q),r,ab,ib,policy.counts)
    return '\n'.join(lines)+'\n'
