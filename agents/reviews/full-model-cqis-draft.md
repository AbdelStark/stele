# E5-03b — Full-model CQIS draft review

Decision: retain Draft; E5-03b remains in progress. This is a checkpoint of the
contract and evidence, not approval to merge or instantiate production behavior.
The same author, codex-root, applies rfc-author, cqis-numerics, gkr-reduction-author
and soundness-auditor. No independent human or agent review is claimed.

Scope: [RFC-0025](../../docs/rfcs/RFC-0025-full-model-cqis.md), its encoding and
decoding/static-arithmetic/consumer appendices, coordinated Draft additions to RFC-0004/0017/0021, and
[the new research evidence](../../research/cqis-model-contract/REPORT.md).
All earlier Accepted text remains an unchanged prefix. No native crate, frozen
oracle, fixture, manifest, benchmark ledger or original proof campaign changes.

## Required Workflow 03 answers

1. **Public items and governing RFC.** The proposed numerical relations are
   RFC-0025 §§2.1–2.6. The encoding appendix specifies physical/source/preparation,
   runtime, public-scale and registry choices. The decoding appendix specifies
   the proposed sampling policy. Research Python has no native consumers and
   cannot promote a Draft RFC to authority. LayerNorm's new FunctionId/mode is
   proposed through RFC-0021 A1; existing descriptors/modes are unchanged.
2. **Challenges and absorption.** No Transcript challenge or absorption is added.
   Seed/draw hashes are deterministic decoding data, not Fiat–Shamir draws.
   Their actual wrapper/seed/source checks and inclusion in global H/query
   accounting remain required before acceptance. A hash digest is not an
   authenticated public input merely because the caller supplies it.
3. **Claims and consumers.** These prototypes emit numerical arrays/metadata,
   not accepted claims. Every original source/scale/gain/bias/index/table/range/
   branch/point obligation remains. The §2.8 inventory is not yet a complete
   bound schema or an actual consuming claim graph. E6/E7/E8 closure is required;
   numerical execution cannot construct a source, PCS or proof-admission handle.
4. **Bindings and controls.** Research controls reject wrong fused parts, partial
   partitions, aliased sources, omitted roles, alias-payload changes, invalid
   metadata, rounding/epsilon/domain errors and CDF boundary mistakes. The flow
   record validator rejects byte/parameter/domain changes; first-maximum ties
   and final-zero carries are checked as arithmetic obligations only. They
   earn no NC coverage. Reserve the new mean/bias/position/FFN/role/tie/config
   controls in the coordinated acceptance change, and retain NC-0100..0109,
   source/lookup/passport and decoding controls at their actual consumers.
5. **Ledger.** No native ledger line, challenge label or profile changes. The
   LayerNorm deterministic error and CDF approximation are not soundness losses.
   Sampling introduces proposed hash-binding uses that must join the existing
   H/query analysis when instantiated. Q12/Q29 remain unresolved. A full
   accounting/registry gate is required before the final PR; draft doc gates
   do not substitute for it.
6. **Static bounds.** The checked LayerNorm derivation depends only on shapes and
   numerical parameters, including all exponent branches; the oracle checks
   intermediates even on output rejection. Runtime matrix scales are authenticated
   parameters in the proposed Scales object, not observed activation bounds.
   The new affine/embedding records retain complete sign/offset/division/
   comparison columns and up to 269 byte positions. Rational/polynomial/struct
   oracles check 10000 configurations per schema; the appendix separately proves
   domain-wide widths, column side bounds and encoded capacity. LayerNorm now
   has a closed 33-role record checked on 10000 configurations and all 33
   normalization branches. Its original row/variance/gain/bias relations and
   common exponent determine the actual offset Ubar; global Ucap is only a bound.
   The maximum-dimension statistic retains RFC-0022's strict field margin.
   Row/residual/gated schemas each have 10000-configuration exact checks. Their
   bounds include static gated scales through 8454661, first-maximum/zero
   branches, complete aligned rounding and the positive gated endpoint 2^30.
   Common whole-word ranges and zero predicates have explicit byte/index bounds.
   Rotary/score/maximum records each have 10000-configuration checks, including
   large coefficient indices and complete exp endpoints. Inadmissible static
   score configurations reject before execution; actual zero inputs cannot
   weaken that rule. Rational unit-circle tests cover the application envelope,
   not canonical configured-frequency generation or public-MLE authentication.
   The full model still needs remaining families, collection bytes
   and actual consuming-reduction closure. No generic opaque certificate or
   caller-selected field is accepted.
7. **Padding and masks.** Source records have exact shapes and no matrix-row
   padding; int4 has only its odd final high nibble. Attention retains absolute
   positions and blocks. The maximum record retains every dense real key, the
   causal mask, first tie and canonical masked delta/gap/index zeros; actual
   masked scores still require their source/arithmetic checks. Actual lookup/zerocheck selectors and public-source MLE
   layouts remain proof-plan requirements. Raw coefficient data/zero padding is
   not proof that padded rows are excluded.
8. **Determinism.** Role/operation order, fused Q/K/V parts, UTF-8 ordering,
   physical payload order, rational encodings, function/representation selection,
   rounding, top-p ties and hash preimages are explicit. Source-map framing,
   raw transforms and the new static records match independent algorithms.
   Extracting the private shared encoder preserves the complete derivation and
   serialization syntax trees, with nine boundary records checked independently.
   Complete runtime/artifact/
   registry/passport codecs and full/cache model flows still need their checks.
9. **Parity.** No CPU/SIMD/CUDA proof parity is claimed. The evidence is exact
   Python arithmetic and independent framing/coordinate/rational oracles. No
   named checkpoint is run by these checkers; named metadata cases only expand
   all roles. The original Rust/NumPy 10000-case per-op gates and full GPT-2-small/
   Llama-3.1-8B parity remain required implementation work.
10. **Cost.** No constant moves and no benchmark is reported. New norm/bias/
    position/decoding work contributes T_witness/c_a/c_lu/T_misc as specified.
    Sampling explicitly charges vocabulary sorting and prefix work. Preparation
    scans are separate from the preserved one online physical-weight pass; a
    tied embedding/head still needs a single-source plan. No extra cut is granted.
11. **Verifier/resources.** Native no_std verifier code is unchanged. Metadata
    lengths/counts and source/scale domains are proposed explicitly; public scale
    data has a separate capacity bound from Model. Research retains Python arrays
    and is not evidence for fallible streaming, full-model memory or hostile
    proof parsing. The named models cannot inherit the old research size caps.
12. **Glossary.** The draft passes the repository glossary gate. It retains the
    distinctions between numerical metadata, bound certificate, claim, source,
    plan, passport, profile and full inference proof.

I tried to break it by changing a fused Q/K/V part, omitting a required role and
changing one byte of the tied-head alias, and the source-map controls rejected it.
That result is limited to the research mapper and does not approve a protocol.

## Findings still preventing acceptance

The complete static-bound collection and consumer expansion, authenticated outer
passport/request schemas, independent full runtime/artifact/registry codecs,
complete GPT-2/Llama numerical-flow integration, sampling's actual exp/request/
seed binding, coordinated accounting/control amendments, and sequential native
implementation DAG remain open. All twelve answers must be revisited against
the final contract before acceptance. Full local and selected hosted gates are
still required before a normal PR merge. No task status is changed to done here.

The operation inventory is now explicit for both full families, including the
missing LayerNorm, GPT-2 activation and wide affine/position delivery work that
the acceptance DAG must name. LayerNorm's new column record supplies arithmetic
metadata only; no native source or proof consumer is added. Existing E7-02 is the
stacked weight phase, E7-09 is dynamic scale attainment and E7-10 is residual/RLC glue; their scopes are
preserved. E13-04's top-k extension remains separate original work. A dependency
name is not proof that its current primitive closes the required source edge.
