# Complete numerical model execution - E5-04

E5-04 implements the Accepted CQIS numerical forward pass and cached generation
for complete GPT-2-small and Llama-3.1-8B models. The executor reads the original
prepared int8/int4 Artifact, retains every layer and vocabulary output, and uses
exact integer arithmetic throughout. This is reference execution; proof,
passport, privacy, fidelity and profile admission remain at their original tasks.

## Original-model qualification

All four original-model comparisons passed. Receipts are copied byte-for-byte
from the frozen qualification outputs and pinned in the [manifest](e504-native-execution/manifest.json).

| Original model | Weight format | Compared bytes | Receipt |
|---|---|---:|---|
| GPT-2-small | int8 | 973360 | [passed](e504-native-execution/gpt2-int8.json) |
| GPT-2-small | int4 | 973360 | [passed](e504-native-execution/gpt2-int4.json) |
| Llama-3.1-8B | int8 | 7228130 | [passed](e504-native-execution/llama-int8.json) |
| Llama-3.1-8B | int4 | 7239570 | [passed](e504-native-execution/llama-int4.json) |

Each manual qualification checks the frozen E5-03c preparation inputs, validates
the entire Artifact, and revalidates the complete original SourcePackage. Native
and independent Python SourceConfig bytes agree for the explicitly selected
runtime Model. Source files, executable, inputs and result digests are pinned.
No checkpoint weights or original residual/logit/cache arrays are committed.
Exact array bytes pass through an anonymous pipe and are compared in memory.

Each original model runs the fixed three-token sequence, a two-token prompt and
two generated positions. Every residual and vocabulary row, every post-rotation
K/V code and whole-row scale, and every decoding argument, weight, permutation,
CDF endpoint and draw is compared. Native cached execution checks every original
position against the single causal pass. Generated tokens, including any EOS,
are evaluated before stopping and the complete final cache is replayed.
These bounded requests retain the complete original model dimensions; they do
not satisfy the separate W8, full-context, fidelity or benchmark requirements.

ADR-058 records the explicit residual/O/down fraction-2 choice. Original embedding
precision and all other units, physical weight formats and original scales stay.
The failed preparation-only settings and reference diagnostics are retained in
[configuration-diagnostics.json](e504-native-execution/configuration-diagnostics.json).
There is no overflow fallback. The changed Model, Scales and SourceConfig have
their own identities; the old four-artifact cqis_id remains attached only to the
original preparation. Definition-only point evaluation does not admit a new
Registry, Bounds collection, table digest or numerical identity.

The frozen numerical executable is SHA-256
09485a5daa7b413c524022db1c73b5523ddb57e638e1d18e41ffaea41dff97aa.
Rebuilding at the final code commit produces those exact bytes. All 139 source
pins in all four receipts match qualified commit
35d5f2ed445c514419af8c5ea5c0695056a10957. The only later change to a pinned file is
in cfg(test) execution tests; the additional integration fixtures are test-only.
The [source audit](e504-native-execution/source-audit.json) records the comparison.

## Numerical and rejection coverage

- Exact-mean affine LayerNorm: 11000 independent NumPy/int64/rational rows,
  including 10731 valid outputs and 269 required overflows; full width 16384,
  epsilon endpoints, singleton/constant rows, signed ties and bias rounding.
- Exact shared scalar operations: 10000 cases each for affine projection,
  embedding addition, residual alignment, attention score and weighted output
  normalization. Full physical exponents, exact cancellation and required range
  failures are retained. Existing row-conversion, RMSNorm and table corpora stay.
- Complete small models: 64 configurations; 17 full accepted cases and 47 typed
  numerical rejections. Every accepted case compares all cuts/logits/cache bytes
  and all cached positions. Fifty-one generation cases cover zero limit, forced
  EOS at the limit and ordinary completion, with wrong-seed checks at zero too.
- Decoding: 10000 rows per greedy/direct/product/corrected mode, checked by the
  independent NumPy and rational/Arb oracles. Includes ties, zero-weight suffixes,
  full product-domain endpoints, temperature domain failures, inclusive top-p,
  complete ordering, exact floor CDF and original absolute-position draws.
- Complete decoding domains: the maximum 1048576-token vocabulary, positive
  weights with two empty CDF buckets, total mass above 2^32, the exact 2^32
  endpoint, and absolute position 1048575. Compact fixtures expand to complete
  ordinary Model/Preparation/Scales/Artifact frames and use the checked API.
- RoPE application: 12000 NumPy/rational rows across all three frequency families,
  adjacent/split layouts and partial rotations; 8749 accepted rows and 3251
  required overflows. Unrotated tails remain byte-identical. Existing 10002
  coefficient cases retain maximum-position and full-parameter coverage.
- Native boundaries: signed absolute 1024-key blocks, masked suffixes, static
  score/block rejection before zero/short execution, memory admission, exact
  request framing, original prompt, EOS precedence, cache scope/geometry/units,
  and both early and final-head append failure. A failed chosen EOS returns no
  Generation and a failed append leaves the caller's immutable cache unchanged.

These numerical tests do not register production negative controls. In
particular NC-0110..0126 remain due at their typed lowering/proof consumers;
wrong-kind rejection and recomputed-output differences alone earn no such credit.

## Acceptance and same-author review

Same author acting in the cqis-numerics and soundness-auditor roles. This is not
an independent review or a cryptographic soundness certification.

1. `Descriptor::evaluate_layernorm` implements RFC-0025 section 2.3 / RFC-0021
   A3. `Executor`, `Full`, `Step` and `Cache` implement sections 2.1 through 2.6 and the
   numerical execution appendix. `Request`, `Decision` and `Generation` implement
   the request and decoding appendices. Accessors expose numerical state only.
2. No Fiat-Shamir challenge, registered label or absorb order changes. Seed
   commitment and sample draw are the existing deterministic decoding hashes;
   they are not reduction challenges or a claim of seed fairness.
3. No proof claim is emitted or consumed. Independently expected Artifact and
   Model/Scales identities scope execution. Source/package checks belong to
   original qualification; the core numerical API grants no publisher authority,
   original conversion proof, authenticated prefix history or source commitment.
4. Numerical rejection tests change the Artifact expectation, each cache identity,
   original seed, prompt, stop reason, cache geometry and units. Wrong LayerNorm
   kind, rounded-mean/bias counterexamples and real range failures are checked.
   The production catalogue is unchanged; no parser/output test replaces a
   reserved control or changes its required error at the actual consumer.
5. No soundness ledger line, loss formula, query count or theorem changes.
   The combined native digest/control/accounting gate passed. Coverage remains
   21/51 bindings, 55/135 controls and one configuration; the 80 missing controls
   remain assigned to their original consuming tasks.
6. All score and complete 1024-key block certificates derive from declared Model
   shapes and units before execution. Every row converter uses its complete
   static record, including full u32 gated scales. Exact wide scalar scratch
   implements the same expression as the checked i128 path; observed maxima
   never relax admission. Proof bound-collection consumption remains separate.
7. Int4 indexing is continuous across physical rows and existing Artifact checks
   enforce final nibble padding. Attention computes all supplied scores, uses
   unmasked keys for max/exp and includes zero masked terms in absolute blocks.
   No new lookup selector, zerocheck padding rule or intermediate commitment exists.
8. All arithmetic and rounding are integer and fixed-order. Whole-row Q/K/V scales
   are inherited by heads/groups. Tied maxima choose the first id; sorting has a
   total weight/id order; sampling hashes the original absolute position. Bounded
   nonlinear caches require complete descriptor/input equality for every hit.
9. All four complete original int8/int4 Rust/NumPy byte comparisons passed. CPU/GPU proof
   parity remains downstream; GPU code is unchanged. Existing native SIMD gates
   retain their host-specific scope and hosted AVX2 validation.
10. This implements unmeasured T_witness reference work. No cost constant is fitted,
    no benchmark number is asserted, and no online proof weight pass changes.
    Full execution owns O(Nv+NLd) arrays plus the borrowed complete Artifact;
    the later recompute-window and serving-performance tasks remain mandatory.
11. Core stays no_std and forbids unsafe code. Shape-derived allocation is fallible
    and admitted under an explicit working-storage budget. The caller-owned
    Artifact/metadata and existing bounded nonlinear scratch have separate scopes.
    The std manual adapter refuses regular-file comparison outputs; failed work
    cannot produce a success receipt. The verifier is unchanged.
12. Existing canonical Model, Preparation, Scales and Artifact meanings remain.
    A numerical cache, point value or result digest provides no proof authority.
    All pre-existing main ADR bytes and Accepted RFC text remain unchanged.

I tried to break it by substituting each cache identity, changing the original
seed at zero generation limit, supplying a short or zero request to an inadmissible
static attention configuration, and selecting an EOS whose evaluation overflows;
the numerical controls rejected them with CacheScope, Seed,
Bounds(ScoreBound/BlockBound) and Range.

The [local gate receipt](e504-native-execution/local-gates.json) records passing
format, Clippy, workspace/example tests, no-default-features checks, native SIMD,
ledger, RFC status, docs, glossary and the combined native gate. The bounded
model-contract checker passed all five groups. Final focused tests passed for
maximum decoding domains and precise static rejection reasons. The initial
new-ADR glossary wording failures were fixed and all glossary tests passed;
the failed initial receipt is retained. Hosted selected CI jobs and a check that
the tested merge tree matches current main remain required before merging.

Manual reproduction uses the release `execute_model` example, the pinned Python
3.12/NumPy/blake3/python-flint/safetensors versions in
`tests/support/qualify_original_execution.py`, the existing complete authorized
E5-03c outputs and original source directory, an explicit native executable,
`--residual-fraction 2`, and a fresh output directory. Source validation and exact
byte comparisons execute again; success receipts are never a validation bypass.
