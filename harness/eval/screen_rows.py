"""E22-02 screen (RFC-0019 R-NUMERICS, Q36 and Q38; Workflow 11 step 3): which activation-row
formats and weight scales keep fidelity when every scale is a power of two.

A float32 simulation. Forward pre-hooks replace the input of every Linear by its
quantise-dequantise value and the weights by theirs. It ranks candidates and splits the gap
by input site. It is not CQIS evidence: only the exact integer executor is (Workflow 11).
The protocol, the candidates and the decision rule are in
`experiments/E22-02-shift-only-rows.md`, committed before any score was seen.

Usage (one H100, about 40 GB of host memory):
    python screen_rows.py --model DIR --out DIR --stage A|B|C|A2|B2|C2 [--windows 8]
Stages A2, B2 and C2 are the addendum of `experiments/E22-02-shift-only-rows.md`.
A config is `weights;site=scheme[bits];...`, for example
`w8p2;attn=static12;out=p2row12;mlp=static12;down=p2row10;head=static12`. Sites left out stay
in float32. Stage C reads the stage B scores from `--out` to build the mixed candidate.
"""
import argparse
import json
import math
import re
from pathlib import Path

import torch

import fidelity as fid

# Input sites: the Linear modules that read each activation tensor.
SITES = {
    'attn': ('q_proj', 'k_proj', 'v_proj'),  # first norm's output
    'out': ('o_proj',),                      # attention output
    'mlp': ('gate_proj', 'up_proj'),         # second norm's output
    'down': ('down_proj',),                  # gated product
    'head': ('lm_head',),                    # final norm's output
}
SCHEMES = ('dynrow', 'dyng128', 'p2row', 'static', 'staticch')
# Addendum: a static scale 2^1 or 2^2 above the calibrated one (room against rejection).
HEADROOM = ('statich1', 'statich2', 'staticchh1', 'staticchh2')
BITS = (8, 10, 12, 16)
BASELINE = 'w8;' + ';'.join(f'{site}=dyng1288' for site in SITES)
CALIBRATION_WINDOWS = 4
# Tolerances of the pre-registered decision rule, as fractions of the float32 perplexity.
SITE_TOLERANCE, COMBINED_TOLERANCE = 0.0005, 0.0025
# Single-matmul code widths: |A| = |sum q*w| stays below 2^30 with int8 weights.
MAX_BITS = {'attn': 12, 'out': 12, 'mlp': 12, 'down': 10, 'head': 12}


def qmax(bits):
    return (1 << (bits - 1)) - 1


def pow2_at_least(s):
    """The least power of two that is at least `s`, element by element (`s > 0`)."""
    return torch.exp2(torch.ceil(torch.log2(s)))


SATURATED = [0, 0]  # elements a static scale clamped, elements converted (per scored config)


def convert(x, scheme, bits, static=None):
    """Quantise-dequantise rows `x[..., d]`. Dynamic schemes scale by the attained maximum
    of the row or of each group of 128 features; `p2*` round that scale up to a power of
    two; static schemes use a calibrated power of two and saturate."""
    q = qmax(bits)
    if scheme in ('dyng128', 'p2g128'):
        inner = 'dynrow' if scheme == 'dyng128' else 'p2row'
        return convert(x.unflatten(-1, (-1, 128)), inner, bits).flatten(-2)
    if scheme in ('dynrow', 'p2row'):
        s = x.abs().amax(dim=-1, keepdim=True).clamp_min(1e-30)/q
        if scheme == 'p2row':
            s = pow2_at_least(s)
    elif scheme.startswith('static'):
        s = static
        # CQIS static rows reject a code outside its width: count what a clamp hides.
        SATURATED[0] += int((torch.round(x/s).abs() > q).sum())
        SATURATED[1] += x.numel()
    else:
        raise ValueError(scheme)
    return torch.round(x/s).clamp(-q, q)*s


def weight(w, kind):
    """Codes per output row. `w8`: int8 at absmax/127. `wBp2`: B-bit codes at the least
    power of two at or above absmax/qmax. `w8mK`: int8 codes at the least scale of the form
    `(2^K + i)·2^e`, `0 <= i < 2^K`, at or above absmax/127 (a K-bit mantissa)."""
    if kind == 'fp':
        return w
    match = re.fullmatch(r'w(\d+)(p2|m(\d+))?', kind)
    if not match:
        raise ValueError(kind)
    q = qmax(int(match.group(1)))
    s = w.abs().amax(dim=1, keepdim=True).clamp_min(1e-30)/q
    if match.group(2) == 'p2':
        s = pow2_at_least(s)
    elif match.group(2):
        steps = 1 << int(match.group(3))
        floor = torch.exp2(torch.floor(torch.log2(s)))
        s = floor*torch.ceil(s/floor*steps)/steps
    return torch.round(w/s).clamp(-q, q)*s


def scheme_bits(value):
    """Split `dyng1288` -> (`dyng128`, 8): the group size is part of the scheme's name."""
    for scheme in ('dyng128', 'p2g128') + HEADROOM:
        if value.startswith(scheme) and value[len(scheme):].isdigit():
            return scheme, int(value[len(scheme):])
    match = re.fullmatch(r'([a-z0-9]*?[a-z])(\d+)', value)
    return match.group(1), int(match.group(2))


def parse_config(config):
    head, *rest = config.split(';')
    sites = {}
    for item in rest:
        site, value = item.split('=')
        scheme, bits = scheme_bits(value)
        assert site in SITES and scheme in SCHEMES + ('p2g128',) + HEADROOM, item
        sites[site] = (scheme, bits)
    return head, sites


class Screen:
    def __init__(self, model_dir, windows):
        from transformers import AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.backend = fid.Fp32(model_dir)
        self.model = self.backend.model
        self.linears = {name: m for name, m in self.model.named_modules() if isinstance(m, torch.nn.Linear)}
        self.site_of = {}
        for name in self.linears:
            for site, suffixes in SITES.items():
                if name.endswith(suffixes):
                    self.site_of[name] = site
        assert set(self.site_of) == set(self.linears), 'every Linear belongs to a site'
        self.original = {name: m.weight.data.cpu() for name, m in self.linears.items()}
        self.windows = fid.wikitext_windows(self.tokenizer)[:windows]
        self.reference = None  # float32 top-1 per window
        self.absmax = None     # name -> per-feature attained maximum on the calibration windows

    def calibrate(self):
        """Per-feature attained maxima of every Linear input on WikiText-2 train windows,
        which share no text with the scored test windows."""
        from datasets import load_dataset
        text = '\n\n'.join(load_dataset('Salesforce/wikitext', 'wikitext-2-raw-v1', split='train')['text'])
        ids = self.tokenizer(text).input_ids
        windows = [ids[i:i+fid.WINDOW] for i in range(0, CALIBRATION_WINDOWS*fid.WINDOW, fid.WINDOW)]
        absmax, hooks = {}, []
        for name, m in self.linears.items():
            def record(_, args, name=name):
                seen = args[0].detach().abs().flatten(0, -2).amax(dim=0)
                absmax[name] = torch.maximum(absmax[name], seen) if name in absmax else seen
            hooks.append(m.register_forward_pre_hook(record))
        with torch.no_grad():
            for w in windows:
                self.model(torch.tensor([w], device=self.backend.device))
        for h in hooks:
            h.remove()
        self.absmax = absmax

    def static_scale(self, name, scheme, bits):
        peak = self.absmax[name].clamp_min(1e-30)
        room = int(scheme[-1]) if scheme in HEADROOM else 0
        if not scheme.startswith('staticch'):
            peak = peak.amax()
        return pow2_at_least(peak/qmax(bits))*(1 << room)

    def install(self, config):
        kind, sites = parse_config(config.removesuffix('@sat'))
        hooks = []
        for name, m in self.linears.items():
            w = self.original[name].to(m.weight.device)
            spec = sites.get(self.site_of[name])
            fold = None
            if spec is not None:
                scheme, bits = spec
                static = self.static_scale(name, scheme, bits) if scheme.startswith('static') else None
                if scheme.startswith('staticch'):
                    fold = static  # per-feature scales fold into the weight columns
                hooks.append(m.register_forward_pre_hook(
                    lambda _, args, s=scheme, b=bits, st=static: (convert(args[0], s, b, st),)))
            # Channel scales are powers of two, so the fold and its inverse are exact.
            m.weight.data = weight(w*fold, kind)/fold if fold is not None else weight(w, kind)
        return hooks

    @torch.no_grad()
    def score(self, config):
        hooks = self.install(config)
        SATURATED[0] = SATURATED[1] = 0
        rows = []
        for i, window in enumerate(self.windows):
            logits = self.model(torch.tensor([window], device=self.backend.device)).logits[0, :-1].double()
            target = torch.tensor(window[1:], device=self.backend.device)
            nll = float(-torch.log_softmax(logits, dim=-1).gather(1, target[:, None]).sum())
            top1 = logits.argmax(dim=-1)
            if self.reference is not None:
                agree = int((top1 == self.reference[i]).sum())
            else:
                agree = len(window) - 1
            rows.append(dict(window=i, nll=nll, tokens=len(window) - 1, agree=agree, top1=top1))
        for h in hooks:
            h.remove()
        return rows


def summarise(config, rows, reference_rows):
    nll, tokens = sum(r['nll'] for r in rows), sum(r['tokens'] for r in rows)
    ref = sum(r['nll'] for r in reference_rows)
    return dict(config=config, ppl=math.exp(nll/tokens), delta=math.exp((nll - ref)/tokens) - 1,
                agreement=sum(r['agree'] for r in rows)/tokens, tokens=tokens,
                saturated=SATURATED[0], converted=SATURATED[1],
                windows=[dict(window=r['window'], nll=r['nll'], tokens=r['tokens'], agree=r['agree']) for r in rows])


ADDENDUM_WEIGHTS = ('w9p2', 'w10p2', 'w8m1', 'w8m2', 'w8m3')


def stage_configs(stage, out):
    if stage == 'A':
        return ['w8', 'w8p2']
    if stage == 'A2':
        return list(ADDENDUM_WEIGHTS)
    if stage == 'B2':
        # Static formats again with saturation counted (`@sat` keeps the stage B rows), the
        # widths between, room above the calibrated scale, and the row format at 9 and 11 bits.
        again = [f'fp;{site}={scheme}{bits}@sat' for site in SITES for scheme in ('static', 'staticch')
                 for bits in (8, 10, 12)]
        between = [f'fp;{site}={scheme}{bits}' for site in SITES for scheme in ('static', 'staticch', 'p2row')
                   for bits in (7, 9, 11)]
        room = [f'fp;{site}={scheme}{bits}' for site in SITES for scheme in ('staticchh1', 'staticchh2')
                for bits in (8, 9, 10)]
        return again + between + room
    if stage == 'C2':
        def mixed(weights, norm_fed, out, down):
            return f'{weights};attn={norm_fed};out={out};mlp={norm_fed};down={down};head={norm_fed}'
        return [
            mixed('w8p2', 'staticch8', 'p2row8', 'p2row10'),
            mixed('w8p2', 'staticch8', 'p2row10', 'p2row12'),
            mixed('w8p2', 'staticch10', 'p2row10', 'p2row12'),
            mixed('w9p2', 'staticch8', 'p2row8', 'p2row9'),
            mixed('w9p2', 'staticch8', 'p2row8', 'p2row10'),
            mixed('w9p2', 'staticch8', 'p2row10', 'p2row12'),
            mixed('w9p2', 'staticch10', 'p2row10', 'p2row12'),
            mixed('w9p2', 'p2row10', 'p2row10', 'p2row10'),
            mixed('w9p2', 'p2row10', 'p2row10', 'p2row9'),
            mixed('w10p2', 'p2row10', 'p2row10', 'p2row10'),
            mixed('w8m2', 'staticch8', 'p2row8', 'p2row10'),
            mixed('w8m3', 'staticch8', 'p2row8', 'p2row10'),
            mixed('w8', 'staticch8', 'p2row8', 'p2row10'),
            mixed('w9p2', 'staticchh18', 'p2row8', 'p2row10'),
            mixed('w9p2', 'staticchh19', 'p2row10', 'p2row12'),
            mixed('w9p2', 'staticch8', 'static12', 'p2row12'),
            mixed('w9p2', 'staticch8', 'p2row8', 'dyng1288'),
        ]
    if stage == 'B':
        return [f'fp;{site}={scheme}{bits}' for site in SITES for scheme in SCHEMES for bits in BITS]
    scores = {r['config']: r['delta'] for r in map(json.loads, (out/'scores.jsonl').read_text().splitlines())}
    uniform = ['w8p2;' + ';'.join(f'{site}={scheme}{min(bits, MAX_BITS[site])}' for site in SITES)
               for scheme in ('static', 'staticch', 'p2row') for bits in (8, 10, 12)]
    return [BASELINE, BASELINE.replace('w8;', 'w8p2;')] + uniform + [mixed(scores)]


def mixed(scores):
    """The pre-registered rule: per site the cheapest format whose single-site delta is
    within SITE_TOLERANCE of the grouped dynamic int8 rows'. Cheapest first: a static
    scale (per tensor, then per feature) at 8, 10, 12 bits, then a power-of-two row scale
    at 8, 10, 12 bits; otherwise the site keeps grouped dynamic rows."""
    chosen = []
    for site in SITES:
        limit = scores[f'fp;{site}=dyng1288'] + SITE_TOLERANCE
        order = [(scheme, bits) for scheme in ('static', 'staticch', 'p2row') for bits in (8, 10, 12)
                 if bits <= MAX_BITS[site]]
        pick = next((f'{s}{b}' for s, b in order if scores[f'fp;{site}={s}{b}'] <= limit), 'dyng1288')
        chosen.append(f'{site}={pick}')
    return 'w8p2;' + ';'.join(chosen)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', required=True)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--stage', required=True, choices=['A', 'B', 'C', 'A2', 'B2', 'C2'])
    parser.add_argument('--windows', type=int, default=8)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out/'scores.jsonl'
    done = {json.loads(line)['config'] for line in path.read_text().splitlines()} if path.exists() else set()
    screen = Screen(args.model, args.windows)
    reference_rows = screen.score('fp')
    screen.reference = [r['top1'] for r in reference_rows]
    if 'fp' not in done:
        with path.open('a') as f:
            f.write(json.dumps(summarise('fp', reference_rows, reference_rows), sort_keys=True) + '\n')
    screen.calibrate()
    for config in stage_configs(args.stage, args.out):
        if config in done:
            continue
        record = summarise(config, screen.score(config), reference_rows)
        with path.open('a') as f:
            f.write(json.dumps(record, sort_keys=True) + '\n')
        print(json.dumps({k: record[k] for k in ('config', 'ppl', 'delta', 'agreement')}), flush=True)


if __name__ == '__main__':
    main()
