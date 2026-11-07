# E5-05 fidelity report: Llama-3.1-8B, fp32 vs CQIS

This report covers RFC-0004 §8 and PRD G7, task E5-05. The model is `meta-llama/Llama-3.1-8B` (base) at the qualified
revision. The CQIS side is the E5-04 prepared Artifact, executed exactly.

## Verdict

| Configuration | Perplexity Δ (≤ 8%) | Benchmarks within paired SE (need ≥ 3) | G7 |
|---|---|---|---|
| int16 residual, fraction 2 (E5-04 / ADR-058 runtime) | +3,061,000% | 0 of 2 measured | **fail** |
| int24 residual, fraction 10 (RFC-0004 §8 wide-path knob; ADR-060) | **+3.24% ± 0.18%** | 0 of 3 | **fail** |

The wide residual knob turns a catastrophic failure into a model that passes the perplexity criterion. The model
stays within a few points on every benchmark, but G7's benchmark criterion is still not met. The residual path is no
longer the limiting factor: the ablation below shows saturation from fraction 8. The remaining gap must come from the
int8 weight, activation and K/V codes. These are the other knobs RFC-0004 §8 names: per-group weight scales,
dynamic scales and attention `B/E` bits. They are follow-up task E5-05b.

## Exactness evidence (prerequisite for every number below)

All CQIS numbers come from `cqis_torch.py`, an exact integer torch executor for the research reference semantics.
- **Arithmetic is int64.** Float64 matmuls are used only where operand maxima prove every partial sum below 2^53.
  `torch._int_mm` is used on CUDA. Products that might exceed int64 fall back to Python integers.
- **Rejections are not silently vectorised.** Any rejection is replayed in reference order, so the typed reason
  matches the reference.
- **Model parity.** `check_cqis_torch.py 1000` compares 1,000 random complete models of both families against
  `model_execution.full`. The models cover int4/int8 codes, static and dynamic rows, every exp mode, every RoPE layout,
  and both exact and blocked accumulation. The run produced:
  - 343 accepted cases and 657 rejected cases;
  - 0 reason mismatches;
  - 821 incremental steps and 500 batched-generation tokens checked against a reference greedy loop;
  - 3 long cases (1,100 keys) that use blocked accumulation;
  - 3,000 normaliser cases.

  This check is the `cqis-torch-parity` exhaustive CI group.
- **Real model.** On the real Llama-3.1-8B Artifact, the executor reproduces the native E5-04 output byte for byte
  (7,228,130 bytes, sha256 `a1a26c5d…`). See `modal_e505.py::parity`.

The wide path (`residual_bits=24`) widens the range checks on the embedding, the residual stream and the O/down
outputs. Everything else stays as in E5-04. The wide path is exploratory semantics: no RFC defines it yet (ADR-060,
follow-up E5-05a). Not one item was rejected in any configuration.

## Protocol

The protocol was fixed in `fidelity.py` before any score was seen.
- **Perplexity:** WikiText-2 raw test, non-overlapping 4096-token windows (71 windows, 289,006 scored tokens).
- **Multiple choice:** zero-shot letter-logit prediction. Ties go to the earlier letter.
- **IFEval:** the raw prompt with greedy decoding and at most 512 new tokens, scored by the lm-eval 0.4.5 checker.
  The pre-registered metric is prompt-level strict accuracy.
- **Statistics:** paired standard errors over identical items, from `summary.py`.
  - The primary G7 reading is |Δ| ≤ paired SE of Δ.
  - The secondary reading is |Δ| ≤ the fp32 score's own SE.
  - The perplexity SE is a ratio estimator over windows.
- **GPQA-Diamond substitution.** GPQA-Diamond is gated, and the run token had no access (HTTP 403). ARC-Challenge
  (1,172 items) is the pre-declared substitute reasoning benchmark. GPQA runs unchanged once someone accepts the
  dataset terms at huggingface.co/datasets/Idavidrein/gpqa.

## Results: wide path (int24 residual, fraction 10)

| Benchmark | n | fp32 | CQIS | Δ | paired SE | fp32 SE | agreement |
|---|---|---|---|---|---|---|---|
| WikiText-2 ppl | 71 windows | 5.8464 | 6.0359 | +3.24% | 0.18% | — | — |
| ARC-Challenge | 1,172 | 79.44% | 76.54% | −2.90 pp | 0.81 pp | 1.18 pp | 92.2% |
| MMLU-Pro | 12,032 | 35.46% | 33.34% | −2.11 pp | 0.33 pp | 0.44 pp | 87.0% |
| IFEval prompt strict | 541 | 8.13% | 9.61% | +1.48 pp | 1.08 pp | 1.18 pp | 93.7% |
| IFEval prompt loose (not pre-registered) | 541 | 10.54% | 10.72% | +0.18 pp | 1.09 pp | 1.32 pp | 93.5% |

Rejections: 0 on every benchmark. IFEval absolute scores are low because this is the base model without a chat
template, as the protocol states. Only the paired comparison is meaningful. The strict IFEval difference favours CQIS,
yet it still exceeds one SE, so it does not count toward G7.

## Results: E5-04 runtime (int16 residual, fraction 2)

This run was stopped early once the failure was unambiguous.

| Benchmark | n | fp32 | CQIS |
|---|---|---|---|
| WikiText-2 ppl | 71 windows | 5.846 | 178,968 |
| ARC-Challenge | 1,172 | 79.44% | 23.46% (chance 25%) |
| MMLU-Pro | 64 | 29.7% | 9.4% |

Fraction 2 leaves a quarter-unit residual. The int16 range forbids any finer fraction, as the ablation shows.

## Ablation: residual width × fraction

The ablation uses the first 8 WikiText windows and the first 300 ARC items. On this subset fp32 scores ppl 5.9694 and
ARC 81.0%.

| Residual | Fraction | ppl | ARC |
|---|---|---|---|
| int16 | 3 | 21,983 | 23.0% |
| int16 | 4 | 10,513 | 22.7% |
| int16 | 5 | 13.97 | 25.3% (collapses to "A") |
| int24 | 8 | 6.1465 | 77.0% |
| int24 | 10 | 6.1424 | 78.3% |
| int24 | 12 | 6.1337 | 78.3% |

No configuration rejected an item. An int16 residual cannot hold both the range and the precision Llama needs. With
24 bits the remaining loss stays flat from fraction 8 to 12, so it lies elsewhere. Fraction 10 was chosen because it is
the middle of the plateau and leaves 13 integer bits of headroom.

## Reproduction and evidence

- `results/e505/summary.r24-f10.json` and `results/e505/summary.r16-f2.json` hold the `summary.py` output.
- `results/e505/items.sha256` holds the sha256 of every per-item JSONL file: the full runs and the ablation. The files
  live on the `stele-e505` Modal volume, under `results/items` and `results/ablation`.
- To reproduce:
  - `modal run harness/eval/modal_e505.py::prepare`, then `::parity`.
  - `::fidelity --tag fp32`.
  - `::fidelity --tag cqis-r24-f10 --fraction 10 --residual-bits 24`.
  - `::ablation`.
  - `uv run --locked --script harness/eval/summary.py DIR cqis-r24-f10`.
- Cost: Modal billed $23.60 through 2026-11-06. The final ~1.3 h on 2026-11-07 was not yet billed when this report
  was written, so the estimated total is about $33 of the $50 cap. The warm executor takes about 0.8 s per 1024-token
  pass on one H100.
