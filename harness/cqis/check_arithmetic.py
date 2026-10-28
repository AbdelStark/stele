# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["numpy==2.3.4"]
# ///
"""RFC-0004 A1 / §5.2: independent NumPy int64 parity, no field proof credit."""
from pathlib import Path
import subprocess

import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def requant(acc, mantissa, shift, bits):
    """Quotient/remainder comparison avoids the Rust implementation's biased sum."""
    product = acc * mantissa
    divisor = np.left_shift(np.int64(1), shift)
    magnitude = np.abs(product)
    quotient, remainder = np.divmod(magnitude, divisor)
    increment = (shift > 0) & (remainder >= divisor // np.int64(2))
    rounded = np.where(product < 0, -(quotient + increment), quotient + increment)
    valid = (rounded >= -(1 << (bits - 1))) & (rounded < 1 << (bits - 1))
    return rounded, valid


def main():
    rng = np.random.default_rng(501)
    lines, expected = [], []
    for bits in (8, 16):
        acc = rng.integers(-(1 << 31), 1 << 31, 10000, dtype=np.int64)
        mantissa = rng.integers(1, 1 << 16, 10000, dtype=np.int64)
        shift = rng.integers(0, 63, 10000, dtype=np.int64)
        values, valid = requant(acc, mantissa, shift, bits)
        assert values.dtype == np.int64 and np.any(valid) and np.any(~valid)
        lines.extend(f'q{bits} {a} {m} {e}' for a, m, e in zip(acc, mantissa, shift))
        expected.extend(f'ok {v}' if ok else 'error Range' for v, ok in zip(values, valid))
        # Exact ties and near-ties in both signs, including target boundaries.
        for e in (1, 2, 8, 16):
            for q in (0, 1, (1 << (bits - 1)) - 1, 1 << (bits - 1)):
                for delta in (-1, 0, 1):
                    for sign in (-1, 1):
                        a = sign * (q * (1 << e) + (1 << (e - 1)) + delta)
                        if not -(1 << 31) <= a < 1 << 31:
                            continue
                        value, ok = requant(np.int64(a), np.int64(1), np.int64(e), bits)
                        lines.append(f'q{bits} {a} 1 {e}')
                        expected.append(f'ok {value}' if ok else 'error Range')
        for acc_edge in (-(1 << 31), -1, 0, 1, (1 << 31) - 1):
            for m in (1, 65535):
                for e in (0, 1, 31, 32, 47, 48, 62):
                    value, ok = requant(np.int64(acc_edge), np.int64(m), np.int64(e), bits)
                    lines.append(f'q{bits} {acc_edge} {m} {e}')
                    expected.append(f'ok {value}' if ok else 'error Range')
        for m, e, error in [(0, 0, 'Scale'), (65536, 1, 'Scale'), (2**32-1, 0, 'Scale'),
                            (1, 63, 'Shift'), (1, 64, 'Shift'), (1, 2**32-1, 'Shift')]:
            lines.append(f'q{bits} 1 {m} {e}')
            expected.append(f'error {error}')
    left = rng.integers(-32768, 32768, 10000, dtype=np.int64)
    right = rng.integers(-32768, 32768, 10000, dtype=np.int64)
    total = left + right
    assert total.dtype == np.int64
    lines.extend(f'add {a} {b}' for a, b in zip(left, right))
    expected.extend(f'ok {v}' if -32768 <= v <= 32767 else 'error Range' for v in total)
    for a in (-32768, -1, 0, 1, 32767):
        for b in (-32768, -1, 0, 1, 32767):
            lines.append(f'add {a} {b}')
            expected.append(f'ok {a+b}' if -32768 <= a+b <= 32767 else 'error Range')
    subprocess.run(['cargo', 'build', '-p', 'stele-cqis', '--example', 'arithmetic',
                    '--locked', '--offline'], cwd=ROOT, check=True)
    result = subprocess.run([str(ROOT/'target/debug/examples/arithmetic')], cwd=ROOT,
        input='\n'.join(lines)+'\n', text=True, capture_output=True, check=True)
    actual = result.stdout.splitlines()
    assert len(actual) == len(expected)
    for i, (got, want) in enumerate(zip(actual, expected)):
        assert got == want, (i, lines[i], got, want)
    print(f'PASS: {len(lines)} Rust/NumPy int64 decisions; 10000 seeded cases per operation plus boundaries/errors')


if __name__ == '__main__':
    main()
