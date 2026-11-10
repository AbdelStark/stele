# RFC-0030 — Security accounting: round-by-round error, Fiat–Shamir and the profiles

Status: Draft · Version: 0.1.0 · Depends: RFC-0002, RFC-0008 (A2, A5), RFC-0010 (A3, A9), RFC-0012, RFC-0027

Resolves Q12 when Accepted. Proposes replacements for RFC-0002 §8 and for the FS line
and total of RFC-0012 §4. Until acceptance those texts stand and no proof is admitted
to `standard` or `treaty`. Tasks: E21-01, E21-04, E12-03.

## 1. Statement

### 1.1 Motivation

- RFC-0012 §4 charges Fiat–Shamir as "hash queries times the largest round error"
  and then requires the *total* to stay below `2^-100` or `2^-128` for an adversary
  with `2^80` or `2^100` queries. That asks every round for `2^-180` or `2^-228`.
- No parameter set meets it. RFC-0010 A3 item 7 shows Policy 1 failing both profiles.
  RFC-0019 Q12 notes that the hash term `Q²/2^256` alone is `2^-56` at `Q = 2^100`.
- Deployed hash-based systems, the public soundness calculator maintained for
  zkVMs, and the one machine-checked inference prover (FlashProve: "about
  q/2^124 + 2^-101") use the convention below. Under it, the query counts RFC-0010 A3
  already derives (`2^-130` per query round) are sufficient.

### 1.2 Definition

A protocol has **round-by-round error** `ε` when, for every round, the probability
over that round's challenge that a doomed prover state becomes not doomed is at most
`ε`. A proof configuration has **λ bits** when `ε ≤ 2^-λ`.

> **Claim of a profile.** For every adversary making at most `Q` queries to the hash,
> the probability of an accepted false statement is at most
> `c₁·(Q + c₂)·2^-λ + H(Q)`, where `H` is the RFC-0012 A15 hash line and `c₁`, `c₂`
> are the constants of the cited compilation theorem.

The theorem is the BCS compilation of a round-by-round sound interactive oracle
proof in the random-oracle model. Acceptance of this RFC pins the exact statement,
its constants and the conditions it places on the transcript (every prover message
absorbed before the challenge that follows it; the first challenge depends on the
full statement, including every model root and the plan digest).

### 1.3 What a ledger reports

The verifier derives, from the plan and the profile only:

- one record per round family with its numerator and denominator (unchanged lines SC,
  RLC, SZ, LU, PCS, MASK);
- `λ_min`, the least `−log2` over all rounds, and the five weakest rounds by name;
- the H line for the profile's query cap.

It rejects a configuration whose `λ_min` is below the profile's target, an evidence
id it does not know, or a record it cannot derive. The sum of interactive terms is
still printed, as information.

## 2. Round errors

| Family | Round | Error | Basis |
|---|---|---|---|
| sumcheck | each round of degree `δ` | `δ/|K|` | Schwartz–Zippel |
| zerocheck | the `eq` point | `m/|K|` | RFC-0006 A3 |
| claim or identity batch | one coefficient, `t` items | `(t−1)/|K|` | RFC-0006 A2 |
| matmul point | `a` coordinates | `a/|K|` | RFC-0012 A14 |
| lookup instance | unit, beta, alpha rounds | RFC-0012 A8 record, `(h + N + c·t − 1)/|K|` for the pair round | RFC-0008 A2, A5 |
| lookup trees | each layer round | `3/|K|`; layer combination `1/|K|` | RFC-0008 A3 |
| commitment, proximity round | tensor of `ℓ` coordinates, radius `e` | `2·ℓ·(e+1)/|K|` | RFC-0010 A3 item 6 |
| commitment, query round | `q` columns | `((N−e−1)/N)^q` or `((N−D+e)/N)^q` | RFC-0010 A3 item 6 |

Each row is an existing interactive bound read per round. No new bound is introduced.

## 3. Profiles

Proposed replacement for RFC-0002 §8:

| | development | standard | treaty |
|---|---|---|---|
| `λ_min` | not claimed | at least 100 | at least 128 |
| bounds | printed, labelled | proven only | proven only |
| grinding | — | not counted | not counted |
| challenge field | QM31 | QM31 | a wider field for every challenge, wide enough that every round clears 128 (about 151 bits under the caps below) |
| zero knowledge | no | optional until RFC-0013 A2 is Accepted | mandatory |
| hash output | 256 bits | 256 bits | 256 bits, leaves domain-separated |

Consequences on QM31 (`|K| ≈ 2^124`), all enforced by plan validation:

- **Lookup instances are capped.** `h + N + c·t − 1 ≤ 2^23`. The plan uses instances
  of at most `2^22` positions with tables up to `2^16` rows. A larger check is split
  by the plan into instances, each with its own multiplicity source and challenges. A
  second challenge pair (`r = 2`) is not required.
- **Commitment rows are capped.** `2·ℓ·(e+1) ≤ 2^23` for every source and level.
- **Batches are capped** at `2^23` items.
- The caps are `2^23`, not `2^24`, because `|K| = p^4` is slightly below `2^124`.
- Sumcheck rounds need no cap (`δ ≤ 4`).

No QM31 round reaches 128 bits: a degree-4 sumcheck round is already `2^-122`. So
`treaty` draws every challenge from a wider field. OM31 is implemented; whether a
186-bit extension is cheaper is decided by measurement (task E12-03, R-OCTIC).

Grinding may be added to any query round. It is reported on its own line and adds
nothing to `λ_min`.

## 4. Verifier algorithm and cost

`stele-verifier::accounting` derives the records of §1.3 while it derives the plan,
before the first transcript absorb, and compares `λ_min` with the profile in the
public input. Cost: linear in the number of round families, independent of the
witness.

## 5. Soundness

This RFC changes how existing terms are combined and what the profiles require. Its
own obligations:

1. the compilation theorem and constants of §1.2, cited exactly;
2. a round-by-round statement for each reduction in §2, with the state function
   named (the composition of RFC-0028 §5 inherits them);
3. the transcript conditions of §1.2 checked against `stele-hash` and the relation
   engine, including the statement-binding order that defeats the known attack on
   Fiat–Shamir for proofs whose statement can encode the hash;
4. a classical random-oracle claim only. Security against quantum adversaries is a
   separate question and is not claimed.

Items 1 and 2 are written in `formal/` for `standard` and are Lean statements for
`treaty`.

## 6. Negative controls

NC-0804 (ledger total tampered) and NC-0805 (profile downgrade) keep their ids.
Proposed, entered at acceptance:

| NC | Tamper | Expected |
|---|---|---|
| 0806 | a plan with one lookup instance above the cap, presented as `standard` | `ProfileBound` |
| 0807 | a source whose evidence id the verifier does not know | `UnsupportedSource` |
| 0808 | a proof that omits one model root from the first absorb | `RoundSumMismatch` at the first challenge-dependent check |

## 7. Open questions

- **Q12** (restated): the exact theorem, constants and query convention; resolved by
  acceptance of this RFC.
- **Q46**: knowledge soundness. The bounds above are soundness relative to the unique
  near codeword (RFC-0010 A3 item 6). A consumer that needs an extractor (recursion,
  the passport binding) must state and prove it.
- **Q47**: the post-quantum claim. Which statement in the quantum random-oracle model
  is defensible for this protocol, and at what loss.

## 8. Amendment log

None.
