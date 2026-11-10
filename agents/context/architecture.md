# Architecture — one page

**Statement (RFC-0001 §3, RFC-0026 §1.1):** a committed model, under CQIS (RFC-0004, RFC-0025), mapped the
published tokens to the published continuation under the stated decoding policy.

## What runs today (development tier, RFC-0026)

```
executor capture (stele-cqis)           every intermediate of the integer forward pass
modules declare + assign (stele-reductions::development)
                                        columns, groups, tables, relations per RFC-0026 §5 row
plain checker (stele-ir::relation)      integer oracle: every relation over Z
relation engine (stele-reductions::relation)
  commit   one stacked source (all witness columns), one model source set, one multiplicity source per table
  prove    zerocheck per domain size · LogUp per table · sumcheck per matmul · claim batch + opening per source
container  stele-dev-e2e-v1 (stele-proof) · CLI prove-dev / verify-dev
```
Everything is committed, weights are read twice, the per-proof code is the v2 expander, no security level is
claimed, CPU only. Measured state: `docs/assessment.md` §3 and `bench/scoreboard.md`.

## Where it is going (build program, RFC-0027; Draft RFC-0028, 0029, 0030)

```
commit   per segment: advice only (rounding outputs, table indices, selections, high limbs)   RFC-0028 §1.2
virtual  accumulators, recombinations, products, remainders: reduced by sumcheck, never opened  RFC-0028 §2
order    segment s: commit → lookups, zerochecks → reduce virtual columns → carry boundary claims;
         open segment s−1; drop it                                                             RFC-0028 §2.4
weights  one stacked phase per weight role; the weight pass is the opening's row combination    RFC-0007 §5, RFC-0029 §1.3
PCS      interleaved circle-RS, BLAKE3 columns, recursive opening; fresh mode (witness),
         certified mode (model); multiplicity sources keep the RFC-0010 A9 form (Q51)          RFC-0029
ledger   per-round error, least bits λ; standard ≥ 100 on QM31 (round numerators ≤ 2^24 − 1),
         treaty ≥ 128 on a wider field                                                         RFC-0030
ZK       bounded-query encodings, mask rows, committed sumcheck masks, opening budget           RFC-0013 A2
```
**What is committed (target):** one or two small integers per nonlinear value; the residual stream at segment
boundaries; multiplicities. **Never committed:** any arithmetic result.
**Field:** M31 base, QM31 challenges (`standard`), wider for `treaty`. **Hash:** BLAKE3.
**Memory:** two segments and the model stream. **Verifier:** derives the plan and the ledger from public data;
never trusts proof-supplied shapes (RFC-0016). **Backends:** scalar reference, SIMD, CUDA, byte-identical (INV-3).
**Crates:** RFC-0020 §1; lanes in RFC-0027 §5. **Cost model:** `docs/cost-model.md`.

The first design (RFC-0001 §4, RFC-0007 §4: residual-only cuts, fifteen stacked stages) is the `treaty` backlog.
Its stacked weight phases and fused opening return as task E18-07; its lookup-over-uncommitted-tensor steps are
replaced by the commit rule.
