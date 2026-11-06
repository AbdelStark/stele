"""E5-05 fidelity harness (RFC-0004 §8, PRD G7): fp32 original vs CQIS, same items, paired SE.

Protocol, fixed before any score was seen (see the E5-05 report):
- Perplexity: WikiText-2 raw test, documents joined by blank lines, tokenized once with
  BOS; consecutive non-overlapping 4096-token windows (the last may be shorter); every
  token after a window's first is scored from its in-window prefix.
- Multiple choice (ARC-Challenge, MMLU-Pro, GPQA-Diamond when accessible): zero-shot
  "Question/A./B./.../Answer:" prompt; the prediction is the largest last-position logit
  among the option-letter tokens " A", " B", ...; ties go to the earlier letter. GPQA
  options are shuffled by a per-question seeded permutation.
- IFEval: raw prompt (base model, no chat template), greedy, at most 512 new tokens,
  stop at <|end_of_text|>; scored by the lm-eval IFEval checker.
- A CQIS rejection (a typed exact-arithmetic failure) scores the item as wrong and is
  counted separately; a rejected perplexity window is excluded and counted.
Floats appear only here, after the exact CQIS logits exist (harness/README.md).
"""
import json
from pathlib import Path
from random import Random

import numpy as np
import torch

LETTERS = 'ABCDEFGHIJ'
WINDOW = 4096
MAX_NEW = 512


def mc_prompt(question, options):
    lines = ''.join(f'{letter}. {str(o).strip()}\n' for letter, o in zip(LETTERS, options))
    return f'Question: {question.strip()}\n{lines}Answer:'


def multiple_choice(name, limit=None):
    from datasets import load_dataset
    items = []
    if name == 'arc':
        for row in load_dataset('allenai/ai2_arc', 'ARC-Challenge', split='test'):
            items.append(dict(id=row['id'], prompt=mc_prompt(row['question'], row['choices']['text']),
                              options=len(row['choices']['text']), answer=row['choices']['label'].index(row['answerKey'])))
    elif name == 'mmlu_pro':
        for row in load_dataset('TIGER-Lab/MMLU-Pro', split='test'):
            items.append(dict(id=str(row['question_id']), prompt=mc_prompt(row['question'], row['options']),
                              options=len(row['options']), answer=row['answer_index']))
    elif name == 'gpqa':
        import csv
        from huggingface_hub import hf_hub_download
        path = hf_hub_download('Idavidrein/gpqa', 'gpqa_diamond.csv', repo_type='dataset')
        with open(path, newline='', encoding='utf-8') as f:
            for i, row in enumerate(csv.DictReader(f)):
                options = [row['Correct Answer'], row['Incorrect Answer 1'], row['Incorrect Answer 2'], row['Incorrect Answer 3']]
                order = list(range(4))
                Random(f'gpqa-diamond-{i}').shuffle(order)
                items.append(dict(id=str(i), prompt=mc_prompt(row['Question'], [options[k] for k in order]),
                                  options=4, answer=order.index(0)))
    else:
        raise ValueError(name)
    if limit is not None and limit < len(items):
        items = sorted(Random(5505).sample(items, limit), key=lambda x: x['id'])
    return items


def wikitext_windows(tokenizer):
    from datasets import load_dataset
    text = '\n\n'.join(load_dataset('Salesforce/wikitext', 'wikitext-2-raw-v1', split='test')['text'])
    ids = tokenizer(text).input_ids
    return [ids[i:i+WINDOW] for i in range(0, len(ids), WINDOW) if len(ids[i:i+WINDOW]) >= 2]


def ifeval_items():
    from datasets import load_dataset
    return [dict(row) for row in load_dataset('google/IFEval', split='train')]


def letter_ids(tokenizer, n=10):
    ids = [tokenizer.encode(' '+letter, add_special_tokens=False) for letter in LETTERS[:n]]
    assert all(len(x) == 1 for x in ids), 'option letters must be single tokens'
    return [x[0] for x in ids]


class Fp32:
    """The original checkpoint in float32 (bf16 weights widen exactly), TF32 disabled."""

    def __init__(self, path, device='cuda'):
        from transformers import AutoModelForCausalLM
        torch.backends.cuda.matmul.allow_tf32 = False
        torch.backends.cudnn.allow_tf32 = False
        self.model = AutoModelForCausalLM.from_pretrained(path, torch_dtype=torch.float32).to(device).eval()
        self.device = device

    @torch.no_grad()
    def last(self, prompts, candidates):
        out = []
        for p in prompts:
            logits = self.model(torch.tensor([p], device=self.device)).logits[0, -1]
            out.append((logits[candidates].double().cpu().numpy(), None))
        return out

    @torch.no_grad()
    def window_nll(self, window):
        logits = self.model(torch.tensor([window], device=self.device)).logits[0, :-1].double()
        target = torch.tensor(window[1:], device=self.device)
        nll = -torch.log_softmax(logits, dim=-1).gather(1, target[:, None]).sum()
        return float(nll), len(window) - 1, None

    @torch.no_grad()
    def generate(self, prompts, max_new, eos, batch=16):
        results = []
        for b0 in range(0, len(prompts), batch):
            group = prompts[b0:b0+batch]
            width = max(map(len, group))
            ids = torch.tensor([[eos[0]]*(width-len(p)) + p for p in group], device=self.device)
            mask = torch.tensor([[0]*(width-len(p)) + [1]*len(p) for p in group], device=self.device)
            out = self.model.generate(input_ids=ids, attention_mask=mask, max_new_tokens=max_new, do_sample=False,
                                      eos_token_id=eos, pad_token_id=eos[0], temperature=None, top_p=None)
            for row in out[:, width:].tolist():
                tokens = []
                for t in row:
                    tokens.append(t)
                    if t in eos:
                        break
                results.append((tokens, None))
        return results


class Cqis:
    """The exact CQIS model through cqis_torch.Executor."""

    def __init__(self, executor):
        self.ex = executor
        self.unit = 2.0**-executor.model.logits_fraction

    def last(self, prompts, candidates):
        out = []
        for p in prompts:
            try:
                _, logits, _ = self.ex.full(p, keep_cuts=False, head_rows=[-1])
                out.append((logits[0, candidates].double().cpu().numpy()*self.unit, None))
            except ValueError as error:
                out.append((None, str(error)))
        return out

    def window_nll(self, window):
        try:
            _, rows, _ = self.ex.full(window, keep_cuts=False, head_rows=False)
            total = 0.0
            for start in range(0, len(window) - 1, 512):
                stop = min(len(window) - 1, start + 512)
                logits = self.ex.finish(rows[start:stop]).double()*self.unit
                target = torch.tensor(window[start+1:stop+1], device=logits.device)
                total += float(-torch.log_softmax(logits, dim=-1).gather(1, target[:, None]).sum())
            return total, len(window) - 1, None
        except ValueError as error:
            return None, len(window) - 1, str(error)

    def generate(self, prompts, max_new, eos, batch=32):
        return self.ex.generate(prompts, max_new, eos, batch=batch)


def done_ids(path):
    if not path.exists():
        return set()
    return {json.loads(line)['id'] for line in path.read_text().splitlines() if line.strip()}


def append(path, record):
    with path.open('a') as f:
        f.write(json.dumps(record, sort_keys=True) + '\n')


def run(backend, tag, tokenizer, out, benchmarks, limits, chunk=64, checkpoint=lambda: None):
    """Score each benchmark into out/<benchmark>.<tag>.jsonl, resuming finished ids."""
    out.mkdir(parents=True, exist_ok=True)
    for name in benchmarks:
        path = out/f'{name}.{tag}.jsonl'
        seen = done_ids(path)
        if name == 'wikitext':
            for i, window in enumerate(wikitext_windows(tokenizer)[:limits.get(name)]):
                if str(i) not in seen:
                    nll, count, reason = backend.window_nll(window)
                    append(path, dict(id=str(i), nll=nll, tokens=count, rejected=reason))
                    checkpoint()
        elif name == 'ifeval':
            items = [x for x in ifeval_items()[:limits.get(name)] if str(x['key']) not in seen]
            eos = [tokenizer.convert_tokens_to_ids('<|end_of_text|>')]
            for c0 in range(0, len(items), chunk):
                group = items[c0:c0+chunk]
                outputs = backend.generate([tokenizer(x['prompt']).input_ids for x in group], MAX_NEW, eos)
                for item, (tokens, reason) in zip(group, outputs):
                    append(path, dict(id=str(item['key']), tokens=tokens, rejected=reason,
                                      response=tokenizer.decode(tokens, skip_special_tokens=True)))
                checkpoint()
        else:
            items = [x for x in multiple_choice(name, limits.get(name)) if x['id'] not in seen]
            candidates = letter_ids(tokenizer)
            for c0 in range(0, len(items), chunk):
                group = items[c0:c0+chunk]
                scored = backend.last([tokenizer(x['prompt']).input_ids for x in group], candidates)
                for item, (logits, reason) in zip(group, scored):
                    record = dict(id=item['id'], answer=item['answer'], rejected=reason, prediction=None, logits=None)
                    if logits is not None:
                        k = item['options']
                        record.update(prediction=int(np.argmax(logits[:k])), logits=[float(x) for x in logits[:k]])
                    append(path, record)
                checkpoint()
