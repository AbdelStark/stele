"""RFC-0024 §2.1 independent static fixtures; no proof or control execution."""
import hashlib
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import requant_schema
from requant_schema import Schema, cases, source_header

ROOT = Path(__file__).resolve().parents[2]
assert Path(requant_schema.__file__).resolve() == ROOT/'tests/negative-controls/requant_schema.py'
P = (1 << 31)-1


def embedded(schema, inner_bits):
    bound = (1 << inner_bits)*128**2
    assert 2*bound < P
    old = schema.constraints()
    boundary, = [i for i, (name, _) in enumerate(old) if name == 'target']
    expected = ([f'input.padding[{i}]' for i in range(4)]
                + [f'advice.padding[{i}]' for i in range(schema.L)]
                + [f'advice.zero[{i}]' for i in range(schema.L, schema.R)])
    assert [name for name, _ in old[boundary+1:]] == expected
    equations = [terms for _, terms in old[:boundary+1]]
    rows = 1 << (schema.L+10).bit_length()
    slack, carry = 5+schema.L, 9+schema.L
    def variable(ordinal): return (1, (ordinal,))
    def real(terms): equations.append([(c, (0, *f)) for c, f in terms])
    for k, v in enumerate(schema.blocks['v'].rows):
        real([variable(5+v), variable(slack+k),
              (0, ()) if k == 0 else variable(carry+k-1),
              (-((bound >> (8*k)) & 255), ()),
              (0, ()) if k == 3 else (-256, (carry+k,))])
    for k in range(3):
        real([(1, (carry+k, carry+k)), (-1, (carry+k,))])
    for row in range(schema.L+11):
        equations.append([(1, (1+row,)), (-1, (0, 1+row))])
    for row in range(schema.L+11, rows):
        equations.append([variable(1+row)])
    assert len(equations) == len(old)-schema.R+rows+3 < 1 << 20
    return bound, rows, equations


def fixtures():
    lines = source_header()+[f'# {Path(__file__).relative_to(ROOT)} '
                             f'{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}']
    configs = [(i % 16, *params, False) for i, params in enumerate(cases())]
    configs += [(0, 1, 1, 8, True), (15, 1, 32, 16, True)]
    for b, mantissa, shift, bits, scalar in configs:
        schema = Schema(mantissa, shift, bits)
        bound, count, equations = embedded(schema, b)
        inputs, physical, outputs = [], [], []
        candidates = [-1] if scalar else [0, -1, 1, -3, 3, -bound, bound]
        for acc in candidates:
            try:
                old = schema.witness(acc)
            except ValueError as error:
                assert str(error) == 'OutputRange'
                continue
            advice = old[1:5]+old[5:5+schema.L]
            slack = bound-abs(acc)
            advice += list(slack.to_bytes(4, 'little'))
            carry, carries = 0, []
            for k in range(4):
                total = ((abs(acc) >> (8*k)) & 255)+((slack >> (8*k)) & 255)+carry
                assert total % 256 == (bound >> (8*k)) & 255
                carry = total // 256
                if k < 3: carries.append(carry)
            assert carry == 0
            advice += carries+[0]*(count-len(advice)-3)
            assert len(advice) == count
            row = [1, *advice]
            for terms in equations:
                value = 0
                for coefficient, factors in terms:
                    product = coefficient
                    for factor in factors: product *= row[factor]
                    value += product
                assert value == 0
            magnitude = (abs(acc)*mantissa+(0 if shift == 0 else 1 << (shift-1))) >> shift
            outputs.append(-magnitude if acc < 0 else magnitude)
            inputs.append(acc); physical.append(advice)
        while len(inputs) & (len(inputs)-1):
            inputs.append(inputs[0]); outputs.append(outputs[0]); physical.append(physical[0])
        assert inputs
        encoded = [len(equations)]
        for terms in equations:
            encoded.append(len(terms))
            for coefficient, factors in terms:
                encoded.extend((coefficient % P, len(factors), *factors))
        lines += [' '.join(map(str, (b, mantissa, shift, bits, schema.L, count))),
                  ' '.join(map(str, inputs)), ' '.join(map(str, outputs)),
                  bytes(v for row in zip(*physical, strict=True) for v in row).hex(),
                  ' '.join(map(str, encoded)), schema.bound_bytes.hex()]
    return '\n'.join(lines)+'\n'


if __name__ == '__main__':
    path = ROOT/'crates/stele-reductions/tests/fixtures/embedded-requant.txt'
    raw = fixtures()
    if path.exists():
        assert path.read_text() == raw, 'existing embedded fixture differs'
    else:
        path.write_text(raw)
    print(f'20 complete embedded static fixtures; SHA256 {hashlib.sha256(raw.encode()).hexdigest()}; no proof or NC credit')
