# /// script
# requires-python = "==3.12.*"
# dependencies = ["lm_eval==0.4.5", "langdetect==1.0.9", "immutabledict==4.2.1", "nltk==3.9.1", "datasets==3.1.0"]
# ///
"""E5-05: paired fp32-vs-CQIS statistics and the PRD G7 verdict from per-item JSONL.

Usage: uv run --locked --script harness/eval/summary.py RESULTS_DIR > summary.json
G7 (docs/prd.md): perplexity ratio - 1 <= 8%, and >= 3 reasoning/instruction benchmarks
"within standard error". Primary reading: |CQIS - fp32| <= the paired standard error of
that difference (RFC-0004 §8 asks for paired SEs). Secondary, reported alongside: the
difference is within the fp32 score's own standard error. A CQIS rejection counts as a
wrong item; any rejected perplexity window fails G7.
"""
import json
import math
from pathlib import Path
import sys


def load(path):
    return {r['id']: r for r in map(json.loads, path.read_text().splitlines()) if r}


def paired(a, b):
    n = len(a)
    d = [y - x for x, y in zip(a, b)]
    mean = sum(d)/n
    var = sum((x - mean)**2 for x in d)/(n - 1) if n > 1 else 0.0
    pa = sum(a)/n
    return dict(n=n, fp32=pa, cqis=sum(b)/n, delta=mean, paired_se=math.sqrt(var/n),
                fp32_se=math.sqrt(pa*(1 - pa)/n), agreement=sum(x == y for x, y in zip(a, b))/n)


def multiple_choice(f, c):
    ids = sorted(set(f) & set(c))
    a = [float(f[i]['prediction'] == f[i]['answer']) for i in ids]
    b = [float(c[i]['rejected'] is None and c[i]['prediction'] == c[i]['answer']) for i in ids]
    out = paired(a, b)
    out['rejected'] = sum(c[i]['rejected'] is not None for i in ids)
    out['same_prediction'] = sum(f[i]['prediction'] == c[i]['prediction'] for i in ids)/len(ids)
    return out


def perplexity(f, c):
    ids = sorted(set(f) & set(c), key=int)
    kept = [i for i in ids if c[i]['rejected'] is None]
    tokens = sum(f[i]['tokens'] for i in kept)
    nf, nc = sum(f[i]['nll'] for i in kept), sum(c[i]['nll'] for i in kept)
    d = nc/tokens - nf/tokens
    residuals = [(c[i]['nll'] - f[i]['nll']) - d*f[i]['tokens'] for i in kept]
    w = len(kept)
    se = math.sqrt(w/(w - 1)*sum(r*r for r in residuals))/tokens if w > 1 else 0.0
    pf, pc = math.exp(nf/tokens), math.exp(nc/tokens)
    return dict(windows=len(ids), rejected=len(ids) - w, tokens=tokens, fp32=pf, cqis=pc,
                ratio_minus_one=pc/pf - 1, ratio_se=math.exp(d)*se)


def ifeval(f, c):
    from datasets import load_dataset
    from lm_eval.tasks.ifeval.utils import process_results
    docs = {str(r['key']): dict(r) for r in load_dataset('google/IFEval', split='train')}
    ids = sorted(set(f) & set(c), key=int)
    scores = {}
    for tag, side in (('fp32', f), ('cqis', c)):
        scores[tag] = [process_results(docs[i], [side[i]['response'] if side[i]['rejected'] is None else ''])
                       for i in ids]
    out = {}
    for key in ('prompt_level_strict_acc', 'prompt_level_loose_acc'):
        out[key] = paired([float(s[key]) for s in scores['fp32']], [float(s[key]) for s in scores['cqis']])
    for key in ('inst_level_strict_acc', 'inst_level_loose_acc'):
        a = [float(x) for s in scores['fp32'] for x in s[key]]
        b = [float(x) for s in scores['cqis'] for x in s[key]]
        out[key] = dict(fp32=sum(a)/len(a), cqis=sum(b)/len(b), n=len(a))
    out['rejected'] = sum(c[i]['rejected'] is not None for i in ids)
    return out


def main(root):
    items = Path(root)/'items'
    report = {}
    for name in ('wikitext', 'arc', 'mmlu_pro', 'gpqa', 'ifeval'):
        f, c = items/f'{name}.fp32.jsonl', items/f'{name}.cqis.jsonl'
        if not (f.exists() and c.exists()):
            continue
        f, c = load(f), load(c)
        report[name] = (perplexity if name == 'wikitext' else ifeval if name == 'ifeval' else multiple_choice)(f, c)
    scored = {k: (v['prompt_level_strict_acc'] if k == 'ifeval' else v) for k, v in report.items() if k != 'wikitext'}
    within_paired = [k for k, v in scored.items() if abs(v['delta']) <= v['paired_se']]
    within_fp32 = [k for k, v in scored.items() if abs(v['delta']) <= v['fp32_se']]
    ppl = report.get('wikitext')
    ppl_ok = ppl is not None and ppl['rejected'] == 0 and ppl['ratio_minus_one'] <= 0.08
    report['g7'] = dict(perplexity_within_8_percent=ppl_ok, within_paired_se=within_paired, within_fp32_se=within_fp32,
                        pass_primary=ppl_ok and len(within_paired) >= 3, pass_secondary=ppl_ok and len(within_fp32) >= 3)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1])
