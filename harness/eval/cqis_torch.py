"""Exact CQIS forward pass in vectorized torch (RFC-0004, RFC-0025 §2), CPU or CUDA.

A port of the research reference research/cqis-model-contract/model_execution.py:
same integer semantics, same typed rejections ('Range', 'RowRange', 'ExpDomain',
'Score', 'Normalization', ...), every value an exact int64. Matrix products run in
float64, which is exact here because every partial sum is an integer below 2^53
(asserted from actual operand maxima), or in int8 x int8 -> int32 on CUDA.
Nonlinear points (activation, exp, RoPE coefficients) come from the same qualified
certifiers as the reference, memoized over the distinct inputs actually used.

This is a fidelity-measurement executor, not a proof or a native replacement:
parity with the reference and the native Executor is checked by check_cqis_torch.py
and by the GPU qualification run recorded in the E5-05 report.
"""
from math import isqrt
from pathlib import Path
import sys

import numpy as np
import warnings
import torch
warnings.filterwarnings("ignore", message="The given NumPy array is not writable")

ROOT = Path(__file__).resolve().parents[2]
for sub in ('cqis-model-contract', 'cqis-tables', 'cqis-checkpoint'):
    sys.path.insert(0, str(ROOT/'research'/sub))
import model_execution as ref  # noqa: E402
import decoding_execution  # noqa: E402
from numerics import LayerNorm, layer_norm  # noqa: E402

I64 = torch.int64
EXACT = 1 << 53


def rr(n, d):
    """Signed round-half-away of n/d for int64 tensors, d > 0 (numerics.round_ratio)."""
    a = n.abs()
    q = a // d
    r = a - q*d
    q = q + (r >= d - r).to(I64)
    return torch.where(n < 0, -q, q)


def checked(x, reason='Range', low=-32768, high=32767):
    if x.numel() and (x.min() < low or x.max() > high):
        raise ValueError(reason)
    return x


def fmatmul(a, b):
    """Exact integer matmul through float64; operands are int64 tensors."""
    bound = a.abs().max().item()*b.abs().max().item()*a.shape[-1] if a.numel() and b.numel() else 0
    assert bound < EXACT, 'float64 product bound'
    return torch.matmul(a.to(torch.float64), b.to(torch.float64)).to(I64)


def normalize(d, F, en, ed, s, a_max=9):
    """certified_rmsnorm.normalize with Python integers, minus its s <= d*2^30 input bound
    (exceeded only by rmsnorm_q version 2's int24 inputs, which use a_max=16): returns (a, M)."""
    n, den = ed*s + en*d*(1 << (2*F)), ed*d*(1 << (2*F))
    a = (n.bit_length() - den.bit_length() - 14)//2
    A, D = (n << (-2*a), den) if a < 0 else (n, den << (2*a))
    if A < 16384*D:
        a -= 1
        A, D = (n << (-2*a), den) if a < 0 else (n, den << (2*a))
    m = A//D
    if not (-23 <= a <= a_max and 16384 <= m < 65536):
        raise ValueError('Normalization')
    return a, m


class Rows:
    """A quantised row batch: int64 codes [T, n], int64 scale [T] (or [T, n/g] for a grouped
    row, RFC-0004 A15), one fraction."""
    __slots__ = ('codes', 'scale', 'fraction')

    def __init__(self, codes, scale, fraction):
        self.codes, self.scale, self.fraction = codes, scale, fraction


class Point:
    """Certified scalar function on [low, high], memoized in a dense device table.

    Only inputs actually used are certified; a certifier rejection is stored and
    re-raised with its reason whenever that input is used again.
    """
    MISSING, FAILED = -(1 << 62), -(1 << 61)

    def __init__(self, function, low, high, device):
        self.function, self.low = function, low
        self.table = torch.full((high - low + 1,), self.MISSING, dtype=I64, device=device)
        self.reasons = {}

    def __call__(self, x):
        index = x - self.low
        values = self.table[index]
        if torch.any(values == self.MISSING):
            for k in torch.unique(x[values == self.MISSING]).tolist():
                try:
                    self.table[k - self.low] = self.function(k)
                except ValueError as error:
                    self.table[k - self.low] = self.FAILED
                    self.reasons[k] = str(error)
            values = self.table[index]
        if torch.any(values == self.FAILED):
            first = torch.unique(x[values == self.FAILED])[0].item()
            raise ValueError(self.reasons[first])
        return values


class Executor:
    def __init__(self, data, device='cpu'):
        """The residual stream, O/down outputs and norm inputs are int24 when the model's norms
        are rmsnorm_q version 2 (RFC-0004 A14), otherwise int16; everything else is unchanged."""
        self.data, self.model, self.device = data, data.model, torch.device(device)
        self.wide = (1 << (ref.width(self.model) - 1)) - 1
        self.shape = s = self.model.shape
        self.int_mm = self.device.type == 'cuda' and hasattr(torch, '_int_mm')
        self.weights, self.vectors = {}, {}
        for name, layer, dims in s.roles():
            if len(dims) == 2:
                self.weights[name, layer] = self._matrix(data.record(name, layer))
            else:
                self.vectors[name, layer] = self._vector(data.record(name, layer))
        if not s.family:
            self.weights['head', -1] = self.weights['token', -1]
        self.exp = {}
        self.activation = {}
        self.ordered = False
        self.replay = True  # False: a rejection raises its unordered reason (sweeps only)
        self.rotation = {}

    # ---- Artifact decoding -------------------------------------------------
    def _matrix(self, r):
        rows, columns = r.dimensions
        raw = np.frombuffer(self.data.raw, dtype=np.uint8, count=r.payload_length, offset=r.payload_offset)
        if r.bits == 8:
            codes = raw.view(np.int8)
        else:
            digits = np.stack((raw & 15, raw >> 4), axis=1).reshape(-1)[:rows*columns].astype(np.int8)
            codes = np.where(digits >= 8, digits-16, digits).astype(np.int8)
        scale = self.data.scales[r.ordinal]
        mantissas = np.frombuffer(scale.mantissas, dtype='<u2').astype(np.int64)
        w = torch.from_numpy(np.ascontiguousarray(codes.reshape(rows, columns))).to(self.device)
        return w, torch.from_numpy(mantissas).to(self.device), scale.exponent

    def _vector(self, r):
        values = np.frombuffer(self.data.raw, dtype='<i2', count=r.elements, offset=r.payload_offset)
        return torch.from_numpy(values.astype(np.int64)).to(self.device)

    # ---- Exact primitives ----------------------------------------------------
    def _dot(self, codes, w):
        """codes [T, k] int64 in [-127,127]; w [n, k] int8 -> exact int64 [T, n]."""
        if self.int_mm and codes.shape[0] > 16 and codes.shape[1] % 8 == 0 and w.shape[0] % 8 == 0:
            return torch._int_mm(codes.to(torch.int8), w.t()).to(I64)
        out = torch.empty((codes.shape[0], w.shape[0]), dtype=I64, device=codes.device)
        step = max(1, (1 << 27)//max(1, codes.shape[1]))
        for start in range(0, w.shape[0], step):
            out[:, start:start+step] = fmatmul(codes, w[start:start+step].to(I64).t())
        return out

    def convert(self, values, fraction, policy, gated=False):
        checked(values, 'Input', -(1 << 30) if gated else -32768, (1 << 30) if gated else 32767)  # as model_execution.convert
        mode, static = policy
        if mode == 2:  # RFC-0004 A15: one dynamic conversion per group of `static` values
            t, n = values.shape
            r = self.convert(values.reshape(t*n//static, static), fraction, (0, 0), gated)
            return Rows(r.codes.reshape(t, n), r.scale.reshape(t, n//static), fraction)
        if mode:
            scale = torch.full((values.shape[0],), static, dtype=I64, device=values.device)
        else:
            scale = (values.abs().amax(dim=1) + 126)//127 if values.shape[1] else torch.zeros(values.shape[0], dtype=I64, device=values.device)
        safe = torch.where(scale == 0, torch.ones_like(scale), scale)[:, None]
        codes = torch.where(scale[:, None] == 0, torch.zeros_like(values), rr(values, safe))
        checked(codes, 'RowRange', -127, 127)
        return Rows(codes, scale, fraction)

    def linear(self, name, layer, x, fraction):
        w, mantissas, exponent = self.weights[name, layer]
        if x.scale.dim() == 2:  # RFC-0004 A15: A' = sum_k s_k*(int8 dot of group k), exact in int64 (< 2^51)
            g = x.codes.shape[1]//x.scale.shape[1]
            acc = sum(self._dot(x.codes[:, k*g:(k+1)*g], w[:, k*g:(k+1)*g].contiguous())*x.scale[:, k, None]
                      for k in range(x.scale.shape[1]))
            scale = torch.ones(acc.shape[0], dtype=I64, device=acc.device)
        else:
            acc = self._dot(x.codes, w)
            checked(acc, 'Accumulator', -(1 << 31), (1 << 31)-1)
            if torch.any((x.scale == 0)[:, None] & (acc != 0)):
                raise ValueError('ZeroScale')
            scale = x.scale
        family = self.shape.family
        bias = None if family or name == 'head' else self.vectors[name+'.bias', layer]
        fb = 0 if bias is None else self.model.formats[self.data.record(name+'.bias', layer).ordinal][1]
        k, kb = exponent - x.fraction + fraction, fraction - fb
        shift = max(0, -k, -kb if bias is not None else 0)
        # The float estimate only flags entries that may leave int64; those use Python integers.
        estimate = acc.abs().to(torch.float64)*mantissas[None, :].to(torch.float64)*scale[:, None].to(torch.float64)*2.0**(k+shift)
        unsafe = estimate >= 2.0**61
        if bias is not None:
            unsafe |= (bias.abs().to(torch.float64)*2.0**(kb+shift) >= 2.0**61)[None, :]
        safe = torch.where(unsafe, torch.zeros_like(acc), acc)*mantissas[None, :]
        n = (safe*scale[:, None]) << (k+shift)
        if bias is not None:
            n = n + (bias[None, :] << (kb+shift))
        out = rr(n, 1 << shift)
        if torch.any(unsafe):
            # Exact Python integers only for entries whose product could exceed int64.
            for t, j in torch.nonzero(unsafe).tolist():
                v = ((int(acc[t, j])*int(mantissas[j])*int(scale[t])) << (k+shift)) + (0 if bias is None else int(bias[j]) << (kb+shift))
                q, r = divmod(abs(v), 1 << shift)
                out[t, j] = (-1 if v < 0 else 1)*min(q + int(2*r >= (1 << shift)), 1 << 40)
        wide = self.wide if name in ('O', 'down') else 32767
        return checked(out, 'Range', -wide - 1, wide)

    def residual(self, x, fx, y, fy, fo):
        le, re = fo - fx, fo - fy
        shift = max(0, -le, -re)
        return checked(rr((x << (le+shift)) + (y << (re+shift)), 1 << shift), 'Range', -self.wide - 1, self.wide)

    def norm(self, spec, x, role, layer=-1):
        gains = self.vectors[role+'.gain', layer]
        if type(spec) is LayerNorm:
            biases = self.vectors[role+'.bias', layer].tolist()
            g = gains.tolist()
            return torch.tensor([layer_norm(spec, row, g, biases)['output'] for row in x.cpu().tolist()],
                                dtype=I64, device=x.device)
        d, F, G, E, en, ed = spec.d, spec.F, spec.G, spec.E, spec.en, spec.ed
        # RFC-0021 A4: version 2 (int24 X) allows exponent a <= 16 and shift <= 97; version 1 a <= 9, shift <= 90.
        a_max, shift_max, x_max = (16, 97, 1 << 23) if spec.version == 2 else (9, 90, 1 << 15)
        s = (x*x).sum(dim=1)
        den = ed*d*(1 << (2*F))
        fast = ed*d*x_max**2 + en*d*(1 << (2*F)) < (1 << 62) and den << 18 < (1 << 62)
        if fast:
            n = ed*s + en*d*(1 << (2*F))
            a = torch.floor(torch.log2(n.to(torch.float64)/(den*16384.0))/2).to(I64).clamp(-24, a_max + 1)
            for _ in range(4):
                big = torch.where(a < 0, n << (-2*a).clamp(min=0), n)
                small = torch.where(a > 0, torch.full_like(a, den) << (2*a).clamp(min=0), torch.full_like(a, den))
                m = big//small
                low, high = m < 16384, m >= 65536
                if not torch.any(low | high):
                    break
                a = (a - low.to(I64) + high.to(I64)).clamp(-24, a_max + 1)
            if torch.any((m < 16384) | (m >= 65536)):
                raise ValueError('Normalization')
        else:
            pairs = [normalize(d, F, en, ed, v, a_max) for v in s.tolist()]
            a = torch.tensor([w[0] for w in pairs], dtype=I64, device=x.device)
            m = torch.tensor([w[1] for w in pairs], dtype=I64, device=x.device)
        if torch.any((a < -23) | (a > a_max)):
            raise ValueError('Normalization')
        v = (1 << 42)//m
        j = torch.sqrt(v.to(torch.float64)).to(I64)
        j = j - (j*j > v).to(I64)
        j = j + ((j+1)*(j+1) <= v).to(I64)
        j = j + ((1 << 44) >= m*(2*j+1)**2).to(I64)
        shift = F + G + 21 + a - E
        if torch.any((shift < -16) | (shift > shift_max)):
            raise ValueError('Shift')
        product = x*gains[None, :]*j[:, None]
        sh = shift[:, None]
        # |product| < 2^53; a left-shifted entry above 2^15 is out of int16 anyway (and could wrap int64).
        if torch.any((sh < 0) & (product.abs() > 32768)):
            raise ValueError('Range')
        left = product << (-sh).clamp(min=0)
        right_shift = sh.clamp(min=0, max=62)  # beyond 62 the rounded magnitude is 0 either way
        half = torch.where(right_shift > 0, torch.ones_like(right_shift) << (right_shift-1).clamp(min=0), torch.zeros_like(right_shift))
        magnitude = (product.abs() + half) >> right_shift
        right = torch.where(product < 0, -magnitude, magnitude)
        return checked(torch.where(sh < 0, left, right))

    def rotate(self, r, x, positions, heads):
        if r is None:
            return x
        width = self.shape.head_width
        pairs = r.width//2
        table = self.rotation.get(r, torch.empty((0, pairs, 2), dtype=I64, device=x.device))
        top = int(positions.max()) + 1
        if top > table.shape[0]:
            extra = [[ref._rotation.__wrapped__(r, p, j) for j in range(pairs)] for p in range(table.shape[0], top)]
            table = self.rotation[r] = torch.cat((table, torch.tensor(extra, dtype=I64, device=x.device).view(-1, pairs, 2)))
        cs = table[positions]                                                # [T, pairs, 2]
        c, s = cs[:, None, :, 0], cs[:, None, :, 1]
        out = x.clone().view(x.shape[0], heads, width)
        j = torch.arange(pairs, device=x.device)
        left = 2*j if r.layout == 0 else j
        right = left + 1 if r.layout == 0 else left + r.width//2
        xl, xr = out[:, :, left], out[:, :, right]
        nl = checked(rr(xl*c - xr*s, 16384))
        nr = checked(rr(xl*s + xr*c, 16384))
        out[:, :, left], out[:, :, right] = nl, nr
        return out.view(x.shape[0], -1)

    def _exp(self, p, t):
        point = self.exp.get(p)
        if point is None:
            point = self.exp[p] = Point(lambda v: decoding_execution.exponential(p, v), -(1 << p.bits), 0, self.device)
        return point(t)

    def _act(self, p, t):
        point = self.activation.get(p)
        if point is None:
            point = self.activation[p] = Point(lambda v: ref.activation.__wrapped__(p, v), -32768, 32767, self.device)
        return point(t)

    def attend(self, layer, q, positions, keys, values, lengths=None):
        """Exact attention, batched over independent sequences.

        Single sequence (lengths None): q Rows [Tq], keys/values Rows [Tk], positions [Tq].
        Batched decode: q Rows [B] (one query per sequence), keys/values with codes
        [B, Tk, G*w] and scale [B, Tk], positions [B], lengths [B] valid keys per sequence.
        Padded keys take no part in any score check, maximum, weight or sum.
        """
        b, s = self.model.blocks[layer], self.shape
        H, G, w = s.heads, s.groups, s.head_width
        dev = q.codes.device
        if lengths is None:
            qc, qs = q.codes[None], q.scale[None]
            kc, ks, vc, vs = keys.codes[None], keys.scale[None], values.codes[None], values.scale[None]
            pos, lengths = positions[None], torch.tensor([keys.codes.shape[0]], device=dev)
        else:
            assert not b.accumulation, 'batched decode supports exact accumulation only'
            qc, qs = q.codes[:, None], q.scale[:, None]
            kc, ks, vc, vs = keys.codes, keys.scale, values.codes, values.scale
            pos = positions[:, None]
        B, Tq, Tk = qc.shape[0], qc.shape[1], kc.shape[1]
        shift = b.score_e - b.fractions[0] - b.fractions[1] + b.exp.F
        exponent = b.attention - b.fractions[2] + b.drop
        qh = qc.view(B, Tq, H, w).transpose(1, 2)                            # [B, H, Tq, w]
        kg = kc.to(I64).view(B, Tk, G, w).transpose(1, 2)                            # [B, G, Tk, w]
        vg = (vc.to(I64).view(B, Tk, G, w)*vs[:, :, None, None]).transpose(1, 2)     # [B, G, Tk, w]
        group = torch.arange(H, device=dev)//(H//G)
        j = torch.arange(Tk, device=dev)
        scope = (j[None, :] < lengths[:, None])[:, None, None, :]           # [B, 1, 1, Tk]
        causal = scope & (j[None, None, :] <= pos[:, :, None])[:, None]      # [B, 1, Tq, Tk]
        out = torch.empty((B, Tq, H, w), dtype=I64, device=dev)
        chunk = 1 if self.ordered else max(1, (1 << 26)//max(1, B*Tq*Tk))
        for h0 in range(0, H, chunk):
            hs = slice(h0, min(H, h0+chunk))
            g = group[hs]
            dot = fmatmul(qh[:, hs], kg[:, g].transpose(2, 3))               # [B, h, Tq, Tk]
            value = dot*qs[:, None, :, None]*ks[:, None, None, :]*b.score_m
            score = rr(value << max(shift, 0), 1 << max(-shift, 0))
            checked(torch.where(scope, score, torch.zeros_like(score)), 'Score', -(1 << 31), (1 << 31)-1)
            maximum = torch.where(causal, score, torch.full_like(score, -(1 << 62))).amax(dim=3, keepdim=True)
            diff = torch.where(causal, score - maximum, torch.zeros_like(score))
            if torch.any(diff < -(1 << b.exp.bits)):
                raise ValueError('ExpDomain')
            weights = torch.where(causal, self._exp(b.exp, diff), torch.zeros_like(diff))
            z = weights.sum(dim=3, keepdim=True)                             # [B, h, Tq, 1]
            scaled = vg[:, g]                                                # [B, h, Tk, w]
            if b.accumulation:
                total = torch.zeros((B, weights.shape[1], Tq, w), dtype=I64, device=dev)
                for start in range(0, Tk, 1024):
                    part = fmatmul(weights[..., start:start+1024], scaled[:, :, start:start+1024])
                    total += checked(rr(part, 1 << b.drop))
            else:
                total = fmatmul(weights, scaled)
            out[:, :, hs] = checked(rr(total << max(exponent, 0), z << max(-exponent, 0))).transpose(1, 2)
        return out.reshape(B*Tq, H*w)

    # ---- Model -----------------------------------------------------------------
    def embed(self, tokens, positions):
        m, s = self.model, self.shape
        w, mant, e = self.weights['token', -1]
        codes = w[tokens].to(I64)
        tm = mant[tokens][:, None]
        if s.family:
            le, shift = e + m.f0, max(0, -(e + m.f0))
            return checked(rr((codes*tm) << (le+shift), 1 << shift))
        pw, pmant, pe = self.weights['position', -1]
        pc, pm = pw[positions].to(I64), pmant[positions][:, None]
        le, re = e + m.f0, pe + m.f0
        shift = max(0, -le, -re)
        return checked(rr(((codes*tm) << (le+shift)) + ((pc*pm) << (re+shift)), 1 << shift))

    def project(self, layer, rows, positions):
        b, s = self.model.blocks[layer], self.shape
        x = self.convert(self.norm(b.norm1, rows, 'norm1', layer), b.norm1.E, b.policies[0])
        q, k, v = (self.linear(name, layer, x, b.fractions[i]) for i, name in enumerate(('Q', 'K', 'V')))
        q = self.rotate(b.rotation, q, positions, s.heads)
        k = self.rotate(b.rotation, k, positions, s.groups)
        return tuple(self.convert(t, b.fractions[i], b.policies[i+1]) for i, t in enumerate((q, k, v)))

    def finish_block(self, layer, rows, positions, q, keys, values, lengths=None):
        m = self.model
        b = m.blocks[layer]
        incoming = m.f0 if layer == 0 else m.blocks[layer-1].out
        attention = self.attend(layer, q, positions, keys, values, lengths)
        o = self.linear('O', layer, self.convert(attention, b.attention, b.policies[4]), b.fractions[3])
        mid = self.residual(rows, incoming, o, b.fractions[3], b.mid)
        x = self.convert(self.norm(b.norm2, mid, 'norm2', layer), b.norm2.E, b.policies[5])
        up = self.linear('up', layer, x, b.fractions[4])
        gate = self.linear('gate', layer, x, b.fractions[5]) if self.shape.family else up
        activated = self._act(b.activation, gate)
        product = up*activated if self.shape.family else activated
        fraction = b.activation.E + (b.fractions[4] if self.shape.family else 0)
        down = self.linear('down', layer, self.convert(product, fraction, b.policies[6], bool(self.shape.family)), b.fractions[-1])
        return self.residual(mid, b.mid, down, b.fractions[-1], b.out)

    def finish(self, rows):
        m = self.model
        x = self.convert(self.norm(m.final_norm, rows, 'final'), m.final_norm.E, m.final_policy)
        return self.linear('head', -1, x, m.logits_fraction)

    def _tokens(self, n):
        if not 1 <= n <= self.shape.context:
            raise ValueError('Length')

    def full(self, tokens, keep_cuts=True, head_rows=None):
        """Single causal pass. Returns (cuts or None, logits, cache).

        head_rows selects the rows whose logits are computed (default: all rows);
        False returns the final residual rows instead, for a caller-chunked head.
        A rejection is replayed in the reference's position/head order, so the
        reported reason is the reference's first failure, not just any failure.
        """
        self._tokens(len(tokens))
        t = torch.tensor(tokens, dtype=I64, device=self.device)
        if t.numel() and (t.min() < 0 or t.max() >= self.shape.vocabulary):
            raise ValueError('Token')
        try:
            return self._full(t, keep_cuts, head_rows)
        except ValueError:
            if not self.replay:
                raise
            self.ordered = True
            try:
                self._full(t, keep_cuts, head_rows)
            finally:
                self.ordered = False
            raise AssertionError('vectorized pass rejected, ordered replay accepted')

    def _full(self, t, keep_cuts, head_rows):
        positions = torch.arange(t.shape[0], device=self.device)
        rows = self.embed(t, positions)
        cuts, cache = [rows] if keep_cuts else None, []
        for layer in range(self.shape.layers):
            if self.ordered:
                parts = [self.project(layer, rows[p:p+1], positions[p:p+1]) for p in range(t.shape[0])]
                q, k, v = (Rows(torch.cat([x[i].codes for x in parts]), torch.cat([x[i].scale for x in parts]), parts[0][i].fraction) for i in range(3))
                rows = torch.cat([self.finish_block(layer, rows[p:p+1], positions[p:p+1], Rows(q.codes[p:p+1], q.scale[p:p+1], q.fraction), k, v)
                                  for p in range(t.shape[0])])
            else:
                q, k, v = self.project(layer, rows, positions)
                rows = self.finish_block(layer, rows, positions, q, k, v)
            cache.append((k, v))
            if keep_cuts:
                cuts.append(rows)
        if self.ordered:
            return cuts, torch.cat([self.finish(rows[p:p+1]) for p in range(rows.shape[0])]), cache
        if head_rows is False:
            return cuts, rows, cache
        return cuts, self.finish(rows if head_rows is None else rows[head_rows]), cache

    def step(self, tokens, cache):
        """Append tokens (one or more) to a cache; returns (cuts, logits, new cache)."""
        start = 0 if cache is None else cache[0][0].codes.shape[0]
        self._tokens(start + len(tokens))
        t = torch.tensor(tokens, dtype=I64, device=self.device)
        if t.min() < 0 or t.max() >= self.shape.vocabulary:
            raise ValueError('Token')
        positions = torch.arange(start, start+len(tokens), device=self.device)
        rows = self.embed(t, positions)
        cuts, new = [rows], []
        for layer in range(self.shape.layers):
            q, k, v = self.project(layer, rows, positions)
            if cache is not None:
                (ok, ov) = cache[layer]
                k = Rows(torch.cat((ok.codes, k.codes)), torch.cat((ok.scale, k.scale)), k.fraction)
                v = Rows(torch.cat((ov.codes, v.codes)), torch.cat((ov.scale, v.scale)), v.fraction)
            rows = self.finish_block(layer, rows, positions, q, k, v)
            new.append((k, v))
            cuts.append(rows)
        return cuts, self.finish(rows), new

    def generate(self, prompts, max_new, eos, batch=32):
        """Greedy decoding (first maximal logit) for many prompts, batched per step.

        Returns, per prompt, (generated tokens, None) or (tokens so far, reason) when the
        CQIS model rejects. A batch step that raises is replayed one sequence at a time,
        so one rejecting sequence never changes another's result.
        """
        results = [None]*len(prompts)
        for b0 in range(0, len(prompts), batch):
            group = list(range(b0, min(len(prompts), b0+batch)))
            self._generate(group, prompts, max_new, set(eos), results)
        return results

    def _generate(self, group, prompts, max_new, eos, results):
        s, L = self.shape, self.shape.layers
        kv = s.groups*s.head_width
        top = max(len(prompts[i]) for i in group) + max_new
        n = len(group)
        kc = [torch.zeros((n, top, kv), dtype=torch.int8, device=self.device) for _ in range(2*L)]
        ks = [torch.zeros((n, top), dtype=I64, device=self.device) for _ in range(2*L)]
        lengths = torch.zeros(n, dtype=I64, device=self.device)
        generated, failed, nxt = [[] for _ in group], [None]*n, [0]*n
        for r, i in enumerate(group):
            try:
                _, logits, cache = self.full(prompts[i], keep_cuts=False, head_rows=[-1])
            except ValueError as error:
                failed[r] = str(error)
                continue
            T = len(prompts[i])
            for layer, (k, v) in enumerate(cache):
                kc[2*layer][r, :T], ks[2*layer][r, :T] = k.codes.to(torch.int8), k.scale
                kc[2*layer+1][r, :T], ks[2*layer+1][r, :T] = v.codes.to(torch.int8), v.scale
            lengths[r] = T
            nxt[r] = int(torch.argmax(logits[0]))
        active = [r for r in range(n) if failed[r] is None]
        for _ in range(max_new):
            for r in active:
                generated[r].append(nxt[r])
            active = [r for r in active if nxt[r] not in eos and len(generated[r]) < max_new]
            if not active:
                break
            try:
                tokens = self._decode(active, nxt, kc, ks, lengths)
            except ValueError:
                tokens = []
                for r in active:
                    try:
                        tokens.extend(self._decode([r], nxt, kc, ks, lengths))
                    except ValueError as error:
                        failed[r] = str(error)
                        tokens.append(None)
            for r, t in zip(active, tokens):
                if t is not None:
                    nxt[r] = t
                    lengths[r] += 1
            active = [r for r in active if failed[r] is None]
        for r, i in enumerate(group):
            results[i] = (generated[r], failed[r])

    def _decode(self, active, nxt, kc, ks, lengths):
        """One greedy step for the active rows; commits K/V only at index lengths[r]."""
        idx = torch.tensor(active, device=self.device)
        tokens = torch.tensor([nxt[r] for r in active], dtype=I64, device=self.device)
        positions = lengths[idx].clone()
        self._tokens(int(positions.max()) + 1)
        if tokens.min() < 0 or tokens.max() >= self.shape.vocabulary:
            raise ValueError('Token')
        top = int(positions.max()) + 1
        rows = self.embed(tokens, positions)
        staged = []
        for layer in range(self.shape.layers):
            q, k, v = self.project(layer, rows, positions)
            K, Ks = kc[2*layer][idx, :top], ks[2*layer][idx, :top]
            V, Vs = kc[2*layer+1][idx, :top], ks[2*layer+1][idx, :top]
            ar = torch.arange(len(active), device=self.device)
            K[ar, positions], Ks[ar, positions] = k.codes.to(torch.int8), k.scale
            V[ar, positions], Vs[ar, positions] = v.codes.to(torch.int8), v.scale
            staged.append((k, v))
            rows = self.finish_block(layer, rows, positions, q, Rows(K, Ks, k.fraction), Rows(V, Vs, v.fraction), positions + 1)
        logits = self.finish(rows)
        for layer, (k, v) in enumerate(staged):
            kc[2*layer][idx, positions], ks[2*layer][idx, positions] = k.codes.to(torch.int8), k.scale
            kc[2*layer+1][idx, positions], ks[2*layer+1][idx, positions] = v.codes.to(torch.int8), v.scale
        return torch.argmax(logits, dim=1).tolist()
