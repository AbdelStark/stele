# RFC-0002 — Threat model, security and soundness requirements

Status: Accepted · Version: 0.1.0

## 1. Setting
Two mutually distrusting parties (e.g. rival states) and a prover operated by one of them. The verifier may be
any third party with a laptop and the public artefacts. The prover is a nation-state-capable adversary with
unbounded engineering budget and physical control of its hardware.

## 2. Assets and goals
| Asset | Goal |
|---|---|
| Statement integrity | a false statement (RFC-0001 §3) is accepted with probability ≤ 2⁻¹²⁸ (treaty) / 2⁻¹⁰⁰ (standard) |
| Weight confidentiality | nothing about `W` beyond `passport_root` leaks to verifiers or the public (treaty: ZK, RFC-0013) |
| Activation confidentiality | same, for prompts/outputs when they are committed rather than published |
| Verifier legibility | the verifier is auditable by the counterparty's own experts (PRD G10) |
| Availability | the prover can refuse; the protocol around it (sampling, deadlines) is out of scope |

## 3. Adversary capabilities assumed
- Chooses all witness data, including degenerate shapes (all-zero rows, padding abuse, repeated tokens).
- Grinds Fiat–Shamir (bounded by work ≤ 2⁸⁰ in standard, 2¹⁰⁰ in treaty; grinding adds to error budget, RFC-0012 §6).
- Finds hash collisions only with negligible probability (Blake3-256, 128-bit collision resistance; treaty profile may require 256-bit outputs for Merkle leaves — RFC-0012 §3).
- Has quantum computers eventually: no discrete-log or pairing assumptions anywhere.
- Controls the serving stack: the proof is about CQIS arithmetic; binding to served traffic is an external protocol (RFC-0011 §5).

## 4. Assumptions
A1 Collision-resistant hash (Blake3-256; Poseidon2-M31 only inside the recursion wrapper).
A2 Fiat–Shamir in the random-oracle model for the interactive IOP (RFC-0012); state-restoration/grinding counted.
A3 Proximity-gap theorems for the chosen codes with the parameters in RFC-0010 §6 (proven: Reed–Solomon up to the
   Johnson bound (BCIKS20), logarithmic randomness (DP23/24), Khatam for general linear codes; **conjectural: none in treaty profile**).
A4 Schwartz–Zippel over `K` for all sumchecks and LogUp identities.

## 5. Non-assumptions (explicitly rejected)
No trusted setup. No TEE. No honest-majority of provers. No tolerance parameters. No “practically never happens”.

## 6. Requirements
- S1 Soundness accounting (`docs/security/soundness-accounting.md`) is machine-generated from the proof config by `stele-verifier::accounting` and shipped inside every proof; the verifier recomputes it and rejects if the budget exceeds the profile's bound.
- S2 All randomness derives from `Transcript` (RFC-0012). The prover has no other source of challenge.
- S3 Every reduction has a stated soundness lemma with a named theorem and explicit degree bound. New reductions ship with `formal/` statements (track R-FORMAL).
- S4 The verifier never trusts prover-supplied shapes; shapes come from `cqis_id` + passport.
- S5 Field-faithfulness certificates (RFC-0004 §6) are recomputed by the verifier from public config.
- S6 Negative-control corpus (§7) passes in CI on every change; coverage metric = bindings with ≥1 control / bindings.
- S7 Determinism (INV-8): no data-dependent control flow in the prover that changes the transcript; padding is canonical.
- S8 Side channels: the prover's weights are secret; GPU timing/power attacks on a self-hosted prover are out of scope, but no weight-dependent *proof bytes* may exist beyond those the ZK argument covers.
- S9 Supply chain: pinned toolchain, vendored or hash-pinned dependencies, reproducible builds of `stele-verifier`, SBOM in releases.
- S10 Two verifiers: Rust `no_std` reference and an independent Python verifier; a proof is “verified” in CI only if both accept and both reject every control.

## 7. Negative-control corpus (public good)
A control is a (proof-generation hook, expected rejection reason) pair. Categories: tampered witness cell, tampered
cut, wrong weights/passport, wrong public input, skipped lookup, inflated multiplicity, out-of-domain table index,
non-attained max, wrong scale, padding abuse, transcript reordering, stale challenge reuse, overflow at the exact
bound, masked-entry leakage, wrong sampling seed. Each control states the RFC section whose check must fire.

## 8. Profiles
| | standard | treaty |
|---|---|---|
| total error | ≤ 2⁻¹⁰⁰ | ≤ 2⁻¹²⁸ |
| PCS bounds | proven preferred, conjectured allowed if labelled | proven only |
| LogUp challenges | 1 (QM31) | 2 independent (ST-6) or octic |
| ZK | optional | mandatory |
| Merkle/hash output | 256-bit | 256-bit, leaves domain-separated |
| grinding allowance | 2⁸⁰ | 2¹⁰⁰ |
