# Plan derivation in the independent verifier (E8-02f2): design note

Status: design only, no code. Decision: ADR-131 (Accepted as a direction). Task: E8-02f2.

## 1. The gap

#381's `stele_verifier::development::verify(public, container, relation, cqis_id)`
replays an RFC-0026 byte-5 proof against a relation **supplied by the caller**. Both
`relation` and `cqis_id` come from outside the verifier.

- The transcript absorbs the public input (Model, Scales, Preparation, 1-D records,
  model roots, `T`, the tokens, `[r, e)` and `y`) and the relation digest.
- Whether the proof says anything about the model, the tokens or `y` depends
  entirely on the relation. A relation that never reads the token one-hot, or never
  checks the argmax, still verifies.
- Today `Ok` therefore means only "the container proves this relation". The
  verifier's own doc comment says so (`# Security`).

This is the largest remaining soundness gap of the independent verifier. RFC-0026 §8
step 2 closes it: the verifier runs every module's `declare` from the plan. The
production verifier (`stele_prover::development::verify`) does this. The independent
one does not yet.

## 2. Scope: what deriving the relation needs

### 2.1 Inputs the verifier must decode and check (RFC-0025)

| Piece | What it computes | Production code |
|---|---|---|
| Model, Scales, Preparation decoding | shape, formats, fractions, policies, mantissas and exponents, rotary layout, function modes | `stele_cqis::model::{codec, shape, scales, preparation, block, rotary}` |
| Registry, Bounds, `NumericalIdentity` | `cqis_id`, which #381 takes from the caller | `stele_cqis::model::{registry, bounds, identity}`, `stele_cqis::bounds` |
| Tables | `exp_q/*`, `rsqrt_q`, `silu_q`, `sign/8` and the other RFC-0021 tables, row for row | `stele_cqis::tables::*`, `stele_cqis::functions` |
| Rotary coefficients | the RoPE public `c`, `s` columns | `stele_cqis::model::rotary` |
| Plan glue | which roles and layers exist; weight list and order (§2.2); 1-D records (A2) | `stele_prover::development::plan` (772 lines) |

These parts total about 2,500–3,000 lines of production code.

### 2.2 The §5 modules: each module's `declare`

The `declare` and `assign` columns count the lines of each method's body. `assign`
is prover-only; the verifier needs `declare` plus the planning and shared-pattern
helpers each module uses (sign/abs, round-half-away division, attained maximum,
limbs, zero-row branch, scale ceilings).

| Row(s) | Module (file) | `declare` | `assign` | Where it is specified |
|---|---|---:|---:|---|
| 1 | embedding gather (`development/embedding.rs`) | 138 | 56 | §5 row 1; ADR-080 (radix-256 chains, one-hot constant selection); A6 note on its blocks |
| 2, 12 | rmsnorm_q (`development/rmsnorm.rs`) | 301 | 117 | §5 rows 2, 12; ADR-080; `research/cqis-bounds/NORM*.md` |
| 3 | row conversion (`development/row.rs`) | 180 | 24 | §5 row 3 and the shared patterns; ADR-076 |
| 4, 12 | projections and head (`development/projection.rs`) | 194 | 17 | §5 row 4; ADR-076; A6 row-block split (ADR-092) |
| 5 | RoPE (`rope.rs`) | 133 | 53 | §5 row 5; A1 (ADR-077) |
| 6–9 | attention: scores, causal max, exp, normaliser, `P̂·V` (`development/attention.rs`) | 565 | 362 | §5 rows 6–9; ADR-079; RFC-0021 §2.1 modes |
| 10 | SiLU gated product (`silu.rs`) | 92 | 49 | §5 row 10; ADR-081 |
| 10 | gated row conversion (`silu/conversion.rs`) | 219 | 14 | §5 row 10, gated-scale ceiling; ADR-081 |
| 11 | residual add (`residual.rs`) | 180 | 46 | §5 row 11; ADR-083 |
| 13 | greedy argmax (`argmax.rs`) | 112 | 33 | §5 row 13; ADR-083 |
| 12–13 | model boundary (`finish.rs`) | 3 | 28 | ADR-083 (it only composes) |
| shared | limbs, byte ranges, development helpers (`development/limbs.rs`, `byte_range.rs`, `development.rs`) | — | — | §3.5a, §5 shared patterns |
| | **total** | **≈ 2,120** | | |

Shared helpers and planning code add about 1,300 lines on top of the `declare` bodies.
The non-`assign` code of these files is about 5,700 lines.

### 2.3 Which parts depend on the statement

Only these public columns depend on the statement. They are easy to compute:

- **Embedding (row 1):** the public one-hot of the tokens, and the gathered token
  mantissa column `m_t` (from Scales). Both depend on the tokens.
- **Argmax (row 13):** `argmax/onehot` (`O[i, v] = [v = c_i]`) and `argmax/below`
  (`[v < c_i]`) on checked rows, and `argmax/rows` (checked rows). They depend on the
  tokens, `[r, e)` and `y`.

Every other column, table, identity, lookup, range, matmul and compose depends only
on (Model, Scales, Preparation, the 1-D records, `T`). `T` fixes the shapes.

## 3. Spec coverage

| Part | Specified exactly in text? |
|---|---|
| Model, Scales, Preparation, the 1-D records | Yes: RFC-0025 §2.7, `full-model-encoding.md`, `full-model-source.md`, `full-model-bound-collection.md` |
| `cqis_id` | Yes: RFC-0025 §2.7 identity join (encoding §6) |
| Tables | Yes: RFC-0021 (generation; canonical table bytes are the integer rows) |
| What each module proves (relation kinds, integer definitions, soundness) | Yes: RFC-0026 §5 rows and shared patterns, ADR-076–ADR-083, the research bounds |
| Each module's exact declaration: column order (`ColumnId`), names, widths, `log_len`, groups, tables, every identity, lookup, range, matmul and compose term, in order | **No, code only.** RFC-0026 §5 describes the relations; it does not fix their encoding |
| Plan glue: module order, weight list, global groups `G/…`, the tied-head alias | Partly: §2.2 fixes the weight order and ADR-085 the module order. Group naming is §2.3; per-module group creation is code |

The relation digest covers every name, width and order. So a verifier that derives
"the same relation up to renaming or reordering" still gets a different digest, and
every proof fails. Derivation must be byte-exact. That means the missing row of the
table above, the exact declaration of every module, must become text before an
independent author can write it (ADR-128's writing rule, as A15 did for the formats).

## 4. Size estimate

| Work | Text | Code |
|---|---|---|
| Spec: one A15-style amendment per module, giving the exact declaration in order (about 11 modules plus the shared patterns and plan glue) | about 2,000–3,000 lines | — |
| Golden vectors: per-module relation encodings at small shapes, plus the one- and eight-layer relation digests | — | about 500 test lines |
| Verifier: CQIS decoding, identity, tables, rotary | — | about 2,000–2,500 |
| Verifier: module declarations and plan glue | — | about 3,500–4,500 |
| **Total** | about 2,500 | **about 6,000–7,000 verifier lines** |

**Budget consequence.** `stele-verifier` is about 3,350 lines on main, plus about
2,300 in #381. Adding about 6,000–7,000 brings it to about 12,000–13,000 lines. That
is inside RFC-0016 §3's 15k limit, with little room left for E8-02g, the full-model
(E8-02) path or the GKR replay. ADR-128's estimate for E8-02f, about 3,500 lines, was
low by a factor of about two: it did not count CQIS decoding and tables.

## 5. Options

**(A) Spec-first, then independent derivation.**
- Per-module amendments (A16…), each transcribed from `declare` with golden vectors,
  each reviewed. Then a fresh author writes the derivation from text alone.
- This is the only option that removes the trust in production's plan code.
- About 2,500 lines of text, 6,000–7,000 of code, and 11+ reviews. Weeks of work.

**(B) Interim: a trusted, versioned plan registry plus independent statement columns.**
- **Registry.** The verifier does not derive the model-dependent part of the
  relation. It checks it against a published registry entry: a *relation template
  digest* for (`cqis_id`, model roots, `T`, profile byte).
- **Statement columns.** It computes the statement-dependent public columns (§2.3)
  itself, from the tokens, `[r, e)`, `y` and the decoded Scales mantissas.
- Small: about 300–500 verifier lines, plus a short amendment and a CLI command that
  publishes entries.
- It binds the tokens, the checked range and `y` independently on every proof. It
  binds the model and the plan to a published, auditable object, made once per
  (model, `T`), not per proof.
- It still trusts production's plan derivation, once per registry entry.

**(C) Interim: per-window canonical relation digest.**
- Publish the digest of the full relation per (model, `T`, tokens, `[r, e)`, `y`).
  The verifier checks the supplied relation's digest against it.
- This cannot be published ahead of time: it changes with every token window. So it
  is only a per-proof attestation by a trusted party. It is weaker than (B).

## 6. Recommendation

Adopt **(B) now and (A) as E8-02f2's goal.**

(B) closes the per-proof soundness gap quickly: the tokens and `y` stop being
prover-chosen. It is honest about its trust root: one versioned, published registry
entry per (model, `T`), produced by the production plan and checkable by anyone with
the production code. (A) then replaces the registry with independent derivation, one
module at a time. Each module that becomes text-specified and independently derived
leaves the template, so (A) can land incrementally.

## 7. Interim proposal in detail (B)

1. **Template.** The relation template is the relation with the §2.3
   statement-dependent public columns' values replaced by zeros. Their names, widths
   and `log_len` are kept, so the column list is unchanged. These columns are
   `embed/…one-hot…`, `embed/…mantissa…`, `argmax/onehot`, `argmax/below` and
   `argmax/rows`; the amendment fixes their exact names.
   - The *template digest* is BLAKE3 of the template's A15 §5 encoding.
   - It depends on (Model, Scales, Preparation, the 1-D records, `T`) only.
   - Its key is (`cqis_id`, model digest = ADR-085 `model_identity`, `T`, profile
     byte).
2. **Registry entry.** `stele plan-digest --model … --scales … --preparation …
   --length T` prints the key and the template digest. It runs the production
   `Layout::declare` with a placeholder statement, then zeroes the statement
   columns.
   - Entries are published next to the model commitment, for example in
     `public.bin`'s distribution or a signed `plan-registry.json`, versioned by the
     plan-code revision.
   - A model owner publishes one entry per `T` they support.
3. **Verifier (E8-02f2-interim)**, given `relation` and a trusted registry entry:
   1. Decode the relation (A15 §5) and validate it (A15 §6.0).
   2. Recompute every statement-dependent public column from the public file: the
      tokens, `[r, e)`, `y`, and the Scales mantissas, which needs only the
      `Scales` decoder for the token matrix. Each must equal the supplied relation's
      column; otherwise `StatementMismatch`.
   3. Zero those columns, take the template digest, and compare it with the
      registry entry for (`cqis_id`, model digest, `T`, byte); otherwise
      `StatementMismatch`.
   4. Replay as #381 does.
   - `cqis_id` and the model digest still come from the caller. The registry entry
     joins them to the template, and an unknown key is `StatementMismatch`.
4. **Spec.** A short RFC-0026 amendment (A16) fixes:
   - the statement-column list, their exact computation and the zeroing rule;
   - the template digest and the registry entry format;
   - pins: the one- and eight-layer template digests and an argmax-column vector.
5. **What it still trusts.** Production `Layout::declare`, once per registry entry,
   and the channel that distributes the entries. The verifier output says so: "plan:
   registry `<digest>`".

## 8. Open points for the ADR review

- Where registry entries live, and who signs them (model owner, or the project for
  public checkpoints such as stories42M).
- Whether the template should also zero the RoPE `c`/`s` columns. Today they depend
  only on the model and `T`, so no.
- The order of the A-series under (A): attention and rmsnorm are the largest (§2.2).
  Starting with argmax, residual and RoPE gives early, small reviews.
