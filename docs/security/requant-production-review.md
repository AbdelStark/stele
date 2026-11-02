# Native Requant production and resource review

E7-01d implements the general native witness and complete untrusted producer for
the closed integer relation in RFC-0023. The existing verifier authenticates every
source, arithmetic claim and output functional. The implementation supports the
specified mantissa, shift and target-format domain under checked resource limits;
the bounded validation matrix does not enumerate every input or parameter tuple.

Implementation commit `0c3547f4dd946816f4e178534a58cc6043fe4ab8`, tree
`e38e316f19050ac2efeb0790c64abf7ad779f968`, is the clean measurement source.
The [complete component ledger](../../bench/ledger/e7-01d-requant.json) is an exact
copy of the emitted file, SHA256
`d3ad45ab19721ec6852e9b570d8424c7c428c3b7bb4017c3828446c1af774626`.
Root checked all 329 raw artifacts, all 36 native/Python pairs, complete receipt
reconstruction and all three deterministic repeats per cell. The raw-audit receipt
SHA256 is `fe4b4fa21bd3cb57171f390da0715f7ae8a2d5673dfb7f043e12a57407337753`.
The ledger retains the external raw paths and hashes; it does not contain model
weights or grant inference/profile admission.

Root completed eleven frozen-source checks: formatting; strict workspace, all-target
and all-feature Clippy; workspace tests; example tests; the scoped no-default-feature
check; the native digest/control/accounting union; ledger validation; RFC status;
documentation links; glossary; and all 78 quick tests. All returned zero with the
same clean implementation head, tree and source hashes. The complete gate receipt
SHA256 is `7e8159f72295013da7aabbe343ab02174124894c653cf15f42eb54ab03496970`;
the native gate log SHA256 is
`f920bc6de5c401c2ef50e0d48c459e4bdaac0d21b7c8bf704befbd4ad0109cdd`.
The no-default-feature command covers sumcheck, lookup and CQIS only. Hosted
validation of the final PR merge tree remains the merge prerequisite.

1. Public items: RFC-0023 §§2.1,2.4,3,6 governs `Schema::witness`, immutable
   `Witness` readers, producer limits, complete `Descriptor::prove` and its Usage
   and failure types. Work types and measured methods report actual capacities
   without creating accepting records. RFC-0006 A3's `prove_with_point` returns
   the actual tail coordinates from the existing loop. RFC-0020 A8 keeps this
   owner specific; no generic accepting reduction interface is introduced.
2. Challenges: production follows the same Statement, two complete A5s,
   Constraints/J weights, aggregate A3, two source groups, output A1 and final
   source-group schedule as verification. Fixed frames precede every independent
   weight. A3/A1 and A9 own their existing draws and final absorbs. Returning a
   point or measuring a capacity adds no challenge or transcript operation.
3. Claims: original byte matrices come from genuine matching prepared sources.
   A3 production returns the actual tail point used for both original/advice
   openings. A1 captures the actual Dense fold arguments for the output group.
   The verifier still reconstructs all functionals from its own actual reductions;
   A7 consumes sigma/Eq and A9 consumes every remaining source claim. All four
   RLC records and all source borrows remain in the opaque accepting record.
4. Bindings: the existing NC-0308..0314 and composed NC-0606/0610/0802 remain.
   NC-0313 now adds positive q=H in both target formats and fields: independent
   candidates have exactly the target residual +1, then actual A3 rejects with
   FinalEvaluationMismatch. The separate native producer failure checks retain
   exact late A3/A1 causes, transcript prefixes, local H and every completed
   registration. They return no partial proof or permission to continue.
5. Soundness: RFC-0012 A13's four independent-vector RLC losses and all existing
   child losses are unchanged. The producer records one final cumulative outer
   snapshot, separate multiplicity production/import observations, and disjoint
   local hashes. One explicit advice-packet identity H is included in its scope.
   Historical reference projection identifies that additional primitive from the
   old actual verifier observation rather than claiming the old producer ran it.
6. Bounds: the existing static schema determines all caps, full-width slacks,
   column carries, identities and padding. Native witness construction uses
   checked integer arithmetic and CQIS output-range decisions. Tests cover all
   63 shifts, both target formats and four mantissa strata, with actual ordered
   equations and overflow rejection. Complete proofs add the 255/256 radix
   boundary and both input source rates. No witness-derived empirical bound
   replaces a verifier-checked static certificate.
7. Padding: both byte matrices begin zero; only real positions are filled.
   Padded input/advice cells, reserved planes, zero caps and shared high columns
   remain in the complete whole-source range lookups and aggregate equations,
   as RFC-0023 requires. Existing false-padding, reserved-plane, full-width-tail,
   source-plane and public-coefficient controls retain their actual consumers.
8. Determinism: the producer uses fixed source, row, term and challenge order.
   There are no retries, transcript replays, zero-weight omissions, floating-point
   prover arithmetic or timing-dependent reductions. Ordinary and measured entry
   points share the same loops. Actual capacities and integer timing observations
   confer no protocol authority.
9. Parity: all ten native-produced wires match the unchanged independent frozen
   wires, including original/advice preparation and full producer registration
   Usage. Their existing 26 saved rejections and following-A1 checks remain.
   The new 36-pair campaign independently verifies every native public request
   and compares all claims, records, imports, Usage, four full weight vectors and
   continuation. Old phase-0 fixtures supply counts only; full vector evidence
   belongs to these new observations. A3 retains its original frozen vectors and
   naive cases, now also checking the returned actual tail. No GPU code changes.
10. Cost: native witness/constraint work is O((4+R+E)N), with the already accepted
    advice cells charged to c_c and both complete byte lookups charged to c_lu.
    A3, output A1 and all three A9 calls remain included. The ledger records
    complete setup/prove/import/two-consumer timings, wire sections and fresh
    process RSS, plus explicitly partial actual capacities. Native RSS includes
    producer, consumer, diagnostics and runtime; it is not an isolated prover or
    exact protocol-owned heap peak. No fitted constant, speedup, weight-pass count
    or inference projection changes.
11. Verifier: no_std, fallible allocation, checked expected lengths and genuine
    certificate borrows remain. Measured verification is the ordinary closed
    path with additional scalar observations. Pre-work admission and late errors
    retain actual Usage and return no accepting record. Existing qualified
    Descriptor/Record compile-fail boundaries and temporary-owner success checks
    remain mandatory. The independent Python entrypoint accepts public data only
    and requires Python 3.12 with assertions enabled.
12. Integration and vocabulary: exact guards cover the new public surfaces and
    all nine private sibling declarations before visibility normalization. The
    separate production fixture inventory leaves the old 59 files unchanged.
    Both existing full corpora and all 13 field-source subprocesses remain.
    The existing quick runner adds two actual radix cases and bounded receipt/
    request mutations; it does not run the resource campaign. No production
    dependency, CI workflow, routing rule or research inventory changes.

The catalogue remains 50 proof controls plus one configuration control out of
104, covering 17 of 32 named binding categories. The 62 declared Requant variants
include two static validations; they are not 62 proof rejections or new IDs.
Broad CQIS controls, configured source/plan authority, the integer matmul bridge,
packing, privacy, profiles, W8 and all parent integration criteria remain open.

I tried to break it by changing target boundaries, carries, prepared contexts,
independent weights, final source paths and following-instance finals. The actual
native controls and independent public-request consumers rejected the changes
for their stated causes. Receipt mutations also rejected omitted capacities,
coupled weight-count truncation, missing imports and incorrect provenance.
