# Native closed Requant verifier review

E7-01d4 closes the conditional Requant relation in RFC-0023 §§2.4,4–6.
An accepting record now requires both range lookups, aggregate arithmetic,
both public coefficients and all three genuine source openings. Native general
witness production, full-domain controls and complete resource ledgers remain
E7-01d obligations. This does not admit a model plan, privacy or inference profile.

Root validation is pinned to implementation commit
`2439e83caad543ae88f88076b29c3a0f7ef87faa`, tree
`0f5aba347a9fe36c6ecc8385a5dba2eaf35d6437`.
Root executed twelve focused checks with source hashes verified before and after.
Receipt SHA256:
`9e20ac2f202aae1efe86f0bee542670c90ed8be037e6b5423be9f91a486ba92c`.
Formatting, strict workspace Clippy, nine Requant unit tests, seven intended
rustdoc failures, four verifier/control tests, the actual control catalogue,
eleven gate regressions, twenty hash tests and policy/documentation checks passed.
The catalogue reports 50 proof controls plus one configuration control, out of 104;
17 of 32 named bindings have executed coverage. Missing families remain explicit.
The exact final PR head must also pass the full hosted workspace/native gates.

1. Public items: RFC-0023 §§2.4,4–5 governs the advice/multiplicity registration
   helpers, complete `Descriptor::verify`, failure Usage and opaque `Record`,
   `GroupRecord` and `RlcRecord`. Only the complete consumer creates an accepting
   record. The Format re-export is the existing CQIS type. RFC-0020 A8 keeps this
   protocol owner specific; no generic accepting reduction interface is added.
2. Challenges: the fixed registry appends three typed absorbs and one independent
   RequantWeight challenge. RequantStatement precedes both actual A5s. The complete
   unsampled constraint frame precedes phase 0 weights; each fixed source/row/id/
   point/value frame precedes its own group weights. Actual A3/A1 and A9 own their
   existing challenges and final/row/response absorbs. All draws use Transcript.
3. Claims: actual A3 emits sigma, four input planes and every advice plane at one
   checked point. A7 consumes sigma; two A9 groups consume all original planes.
   Actual output A1 emits Eq, sign and ascending q planes; A7 consumes Eq and the
   third A9 consumes the remaining claims. Zeros remain in every roster and
   weighted polynomial. The record retains both A5s, A3, A1, three A9s and four RLCs.
4. Bindings: NC-0308..0314 cover input aliasing, advice context, full-width result,
   carries, plane mapping, sign-at-zero and padding. NC-0606 adds genuine advice
   substitution; NC-0610 tests weight swaps and omissions separately in four phases;
   NC-0802 tests six frame omissions independently through a genuine following A1.
   Both A7 checks have direct controls. Sigma changes one semantic public claim
   with dependent arithmetic messages: actual A3 accepts before A7 rejects. Its
   unchanged suffix is unreachable and grants no later-consumer evidence.
5. Soundness: RFC-0012 A13 assigns four independent-vector RLC losses of 1/|K|;
   actual child records retain their separate losses. These are not A2 powers.
   The outer Usage snapshots its cumulative transcript once and sums only the
   advice identity H plus disjoint child-local H, including a failed child's prefix.
   Advice and ordered multiplicity imports retain separate attempted Usage.
   No profile total or Fiat–Shamir theorem is inferred. The native union checks
   the updated registry/accounting with all previous consumers.
6. Bounds: generated CQIS records and fixed geometry determine every integer
   identity, term, count and ID. The scoped NC-0109 check rejects an altered
   bound encoding through the actual static validator. No observed witness range
   replaces a static certificate; broad CQIS catalogue completion remains pending.
7. Padding: both whole-source range_8 lookups include all physical bytes. The
   aggregate retains sigma masks, input/advice padding equations and zero reserved
   planes. The new padded-input candidates keep the original statement, genuine
   handles and complete A5 prefix fixed. Their exact aggregate-A3 rejection and
   import/failure Usage agree with the separate bounded reference construction.
8. Determinism: fixed source, equation, term, claim and byte orders are retained.
   There are no map-based reductions, challenge retries, skipped zero weights,
   injected randomness, state imports or verifier bypasses.
9. Parity: the unchanged frozen corpus supplies ten accepts and 26 saved rejects
   across QM31/OM31, both repetition counts and scalar/padded cases. Native tests
   compare full child records, ordered groups, imports, outer Usage and following-A1
   continuation. Phases 1..3 compare saved weight vectors directly; phase 0 compares
   the total draw count and is constrained by actual arithmetic, Usage and
   continuation, without claiming a saved gamma-vector comparison. There are 58
   additional declared variants, including two static-bound validations; this is
   not a count of 58 proof rejections. No GPU code changed or GPU parity is claimed.
10. Cost: T_misc adds O(N+E+P+J+m) verifier work plus existing child consumers.
    Concrete aggregate, claim, point and frame allocations are checked before
    replay. Complete wire and cumulative public/import limits precede execution.
    No weight pass or measured constant changes; no benchmark result is claimed.
    Full preparation/prove/import/verify/peak-memory ledgers remain parent work.
11. Verifier: the crate remains no_std with fallible owned buffers and checked
    expected lengths. Advice context and exact certificate identity precede
    RequantStatement; each actual A5 keeps its own multiplicity identity boundary.
    Failed imports expose observations without partial handles; failed verification
    exposes no accepting record. Four Record owner-escape examples and two
    Descriptor examples produce E0515; the nonexistent constructor produces E0599.
    Temporary schema, point, proof and descriptor owners may die after acceptance.
12. Vocabulary and integration: the code follows the Accepted source/plane/claim
    names. Exact API and evidence guards preserve old corpora and all 13 existing
    field-source subprocess calls. The 59-file fixture inventory and generator
    sources are pinned; historical temporary paths are provenance only. CI routing,
    dependencies and job count are unchanged.

Root validation statement: I tried to break it by substituting genuine advice,
aliasing the integer input, changing carries and source rows, omitting independent
weights and transcript frames, and supplying false public coefficients. The actual
NC-0308..0314, composed NC-0606/0610/0802 and direct A7 controls rejected the
changes for their stated causes. The scoped signed-tie/remainder and static-bound
checks do not complete the broad CQIS family.

The change exceeds the repository's approximately 800-line guidance because the
new accepting consumer, every new binding control and pinned independent evidence
must ship together. The prior schema/constraint/codec slices are already merged;
general production and resource-ledger work remain separate sequential tasks.
No acceptance check was deferred to reduce this PR's size.

The soundness/PCS, GKR/control and CI/evidence reviewers inspected the frozen
source and all twelve root-run logs and approved this scope, subject to final
hosted validation. Their full twelve-item review SHA256 values are respectively:

- `4e953aff019ab9eb72b3c2d4aa28451848e3ac4edf3c6034917abdfb4e31a0d3`
- `4bf17748bd2db45178310409f093d0a26928cc205bf512dd831e11b81d5066d8`
- `39f3e2fb498373351ff612004f533e4490f7a4fe11625753672bc42aa4027854`
