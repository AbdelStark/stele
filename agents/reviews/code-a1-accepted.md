# RFC-0010 A1 / RFC-0012 A7 acceptance review

Reviewer: claude-code, as pcs-engineer/stele-code owner, rfc-author and soundness-auditor.
The reviewer also wrote the acceptance text, so this is not an independent audit. Acceptance
follows the repository owner's instruction (2026-11-06) to resolve blocking Draft amendments
autonomously. That instruction removes the wait for a separate human sign-off. It does not
remove the Workflow 02 checks recorded below.

Decision: accept A1's identity, distance-evidence, registry-authority and resolver contract,
and A7's separate setup event. E4-01 becomes ready. No PCS parameter set, proximity radius,
query count or profile is admitted. Those remain with A3, A6 and A7 (RFC-0010), and Q12.

## Open requirements of A1 (Q23), item by item

1. **Construction.** The v2 recursive map (formal/recursive-code.md), with the Accepted A2
   circle base, is fixed and natively delivered by A4/E4-08. Its finite distance bound,
   `D = floor(k/25) + 1` for J ≥ 4 and 64 for J = 3, is evidence `rfc-0010-a1/finite-v2`
   (formal/expander-sampling.md).
   - The reviewer re-checked the induction: `D_inner = floor(n/100) + 1` equals the previous
     level's `floor((n/4)/25) + 1`, and the weight case split covers every nonzero codeword.
   - The reviewer re-checked the elementary `C(m,k) ≤ (3m/k)^k` step and the four interval
     constants. `G_A(10)`, `G_B(18)`, `E_A` and `E_B` raised to the 128th power are all
     ≤ 2^-516, against the 2^-416 required.
   - The bound holds for the uniformly sampled ensemble only. A7 transfers it to every
     regenerated seed.
2. **Setup and identity.** The 21-byte Circle and 55-byte v2 identities are fixed by A2/A4.
   - A7's all-seed union bound was re-derived independently with exact rationals:
     `L = Σ_{j=4..15} 2((D_j−1) + (D_j−I_j)) = 200431782` and
     `2^256 · L / 2^416 = 200431782/2^160 ≈ 2^-132.42`.
   - The pointwise argument holds: B is an event over the oracle alone, so outside B every
     seed is good, whatever the selection strategy, classical or quantum.
   - The random-oracle premise for BLAKE3 is labelled as an assumption, not proven.
   - Binding the code ID into commitment, plan and passport descriptors is left to the
     consumers that create those descriptors, as the A1 text requires.
3. **API.** The sealed `Code` trait and `Encoder::from_code_id` exist (A4). A1 adds a native
   two-entry catalog and a fail-closed parameter resolver, delivered by E4-01. Unknown,
   duplicated, reordered or edited registry data is rejected as `InvalidRegistry`. Every PCS
   parameter request returns `UnsupportedParameters` until A3 admits a query policy.
4. **Distance and proximity are kept separate.** Distance and setup evidence are recorded under
   immutable evidence IDs. A3 owns the proximity radius, the exceptional-combination term and
   the query count. The conditional arithmetic in check_proximity/check_certified, for example
   `q = 13472` at n = 2^30, is not admitted here. No term enters §6 or the ledger until
   profile admission.
5. **Tests and controls.** E4-08 delivered native vectors, linearity and parity in all three
   fields, plus rejection of malformed inputs. E4-01 must add a one-sided distance-estimate
   script and resolver substitution tests. NC-0612 is reserved as `todo` for
   code-ID/evidence substitution under the first actual expander PCS consumer (E4-03).
   Research counterexamples earn no NC credit.
6. **Cost.** A5 and E4-08 ledgers (bench/ledger/e4-08-native-bounded-encoder.json) cover
   adds per element, preparation and memory. E4-01 must still publish its adds/element
   ledger entry.

## Checklist

- **Challenges/absorbs:** none added. Setup expansion is not Fiat–Shamir.
- **Ledger:** A7 defines a separate setup term, charged in addition to the protocol error
  under good setup. It enters a profile only together with Q12's FS/H composition.
- **Certificates:** derived parameters come from exact identity integers and are never
  accepted as inputs.
- **Determinism:** unchanged (A4).
- **Verifier:** no production change in this acceptance.
- **Glossary:** encoder information, distance evidence, setup evidence, registry authority and
  PCS admission are distinct terms.

## Evidence run by the reviewer

The following commands all passed on 2026-11-06:
- `python3 research/code-provenance/check_code.py` and `check_expander.py`;
- `uv run --locked --script research/code-provenance/check_{recursive,sampler,identity,proximity,certified,bounded}.py`.

Sign-off: accept A1 and A7 as above. E4-01 is ready, with all of its original acceptance
criteria intact.
