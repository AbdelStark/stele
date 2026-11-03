# E5-03b — Full-model CQIS draft review

Decision: retain Draft; E5-03b remains in progress. This is a checkpoint of the
contract and evidence, not approval to merge or instantiate production behavior.
The same author, codex-root, applies rfc-author, cqis-numerics, gkr-reduction-author
and soundness-auditor. No independent human or agent review is claimed.

Scope: [RFC-0025](../../docs/rfcs/RFC-0025-full-model-cqis.md), its encoding and
decoding/static-arithmetic/consumer appendices, coordinated Draft additions to RFC-0001/0004/0017/0021, and
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
   RFC-0001 A1 now proposes exact request-policy and TokenIO subrecords; the
   request appendix specifies EOS sets and schema 18. Accepted text is preserved
   as an exact prefix, with no production use of the Draft amendment.
   The complete structural Model codec implements encoding appendix §4 only;
   Registry/Bounds/source admission remains a separate required step.
   The complete Scales codec now implements appendix §5's matrix-only frame.
   Registry now implements §6's complete function/component/rotation set and
   compares all data digests with regeneration under the declared definitions.
   The physical appendix adds schema 19 for canonical tensor/code/scale addresses.
   The collection appendix fixes all nineteen schemas' ordered slots and complete
   Model/Scales/Registry parameter selection, with exact outer framing.
2. **Challenges and absorption.** No Transcript challenge or absorption is added.
   Seed/draw hashes are deterministic decoding data, not Fiat–Shamir draws.
   Their actual wrapper/seed/source checks and inclusion in global H/query
   accounting remain required before acceptance. A hash digest is not an
   authenticated public input merely because the caller supplies it.
   The Model expected-digest check has exactly that content-only limitation.
   Scales binds full H(Model); its expected digest likewise needs authentication.
   Registry derives its expected definitions from Model, whose source/passport
   authority is still required. Its deterministic checks add no FS challenge.
   Physical address derivation adds no challenge or absorption either.
   Bounds binds all three complete input hashes without a cqis_id cycle. These
   content joins still require independently authenticated expected inputs.
3. **Claims and consumers.** These prototypes emit numerical arrays/metadata,
   not accepted claims. Every original source/scale/gain/bias/index/table/range/
   branch/point obligation remains. The §2.8 inventory does not instantiate
   an actual consuming claim graph. E6/E7/E8 closure is required;
   numerical execution cannot construct a source, PCS or proof-admission handle.
   Model's typed fields provide derivation parameters; they are not claims and
   do not discharge table validity or static score/full-block admission.
   Scales provides every configured channel, with source minimality and the
   artifact/passport equality obligations still owned by their consumers.
   Complete Registry data validation does not supply a coded public-source root,
   lookup membership, point binding or a full-model certificate.
   Schema 19 supplies coordinate/byte/code/scale bounds. Artifact-global and
   original source-container joins still belong to their actual consumers.
   Fixed collection slots preserve every physical and numerical role. Weighted's
   shared record retains its separate probability/block/global consumers.
4. **Bindings and controls.** Research controls reject wrong fused parts, partial
   partitions, aliased sources, omitted roles, alias-payload changes, invalid
   metadata, rounding/epsilon/domain errors and CDF boundary mistakes. The flow
   record validator rejects byte/parameter/domain changes; first-maximum ties
   and final-zero carries are checked as arithmetic obligations only. They
   earn no NC coverage. Reserve the new mean/bias/position/FFN/role/tie/config
   controls in the coordinated acceptance change, and retain NC-0100..0109,
   source/lookup/passport and decoding controls at their actual consumers.
   Request research controls reject prompt substitutions, early stopping,
   continuation after EOS, wrong cause at the limit, invalid EOS order/range,
   inactive seed fields, malformed bytes and a field-congruent u32 token change.
   They do not replace NC-0001/0005/0107/0108 at actual proof/hash consumers.
   Model controls reject broken physical/norm/unit/family joins and conflicting
   representations. Of 10000 bit changes, 9697 fail structural checks; 303 are
   changed canonical models and fail the original expected-digest join.
   Scales bit changes produce 1286 structural and 8714 expected-digest
   rejections. Same-shaped numerical Model substitution rejects separately.
   Registry controls reject changed role/definition bytes, every data-digest
   slot and a digest recomputed from a corrupted canonical rsqrt frame. A
   structurally valid activation configuration whose full table overflows rejects.
   All 10000 randomized bit mutations and 1842 fixture-byte mutations reject.
   Physical-record mutations and changed expected fractions reject; complete
   word examples distinguish field-congruent addresses. That distinction earns
   no native source-binding or NC coverage.
   Collection controls target omission, duplication, source hashes, stale records
   under changed formats, forged Registry data and static admission failures.
   Those controls pass, including full-table overflow and block rejection at
   n=1. The final-duplicate control expects Trailing after exact exhaustion.
5. **Ledger.** No native ledger line, challenge label or profile changes. The
   LayerNorm deterministic error and CDF approximation are not soundness losses.
   Sampling introduces proposed hash-binding uses that must join the existing
   H/query analysis when instantiated. Q12/Q29 remain unresolved. A full
   accounting/registry gate is required before the final PR; draft doc gates
   do not substitute for it.
   Model hashing adds no native hash query here; complete identity accounting
   remains acceptance work.
   The Scales research hash joins do not instantiate native H/query accounting.
   Registry's complete data hashes remain part of the pending global accounting.
   The physical record adds deterministic word relations, with no new loss term.
   Collection hashing adds no native loss line here; complete H accounting
   remains part of the coordinated acceptance work.
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
   Exp/activation records each have 10000-configuration column/byte checks.
   They retain every component's inclusive index and complete signed source
   words. Selected certified point evaluations exercise recombination and
   overflow; they do not admit an entire table. A bounded activation record
   for invalid full-table parameters grants no execution authority.
   Weighted/normalization records each have 10000-configuration checks. Fixed
   radix-16 columns cover context 2^20; full-block admission remains mandatory
   even at capacity one. The exact offset uses the actual probability sum.
   Variable division uses Dmin to bound its quotient; a reachable output 128
   demonstrates why using Umax/Dmax=127 would reject a valid result.
   The original RMSNorm chain now has a complete record checked on 10000
   configurations, plus actual boundary cases at all 33 exponents. Original
   input/gain signs, statistic remainders, shared normalization/output factors,
   reciprocal indices and exact signed output remain separate obligations.
   A mixed factor tuple can pass individual ranges without corresponding to
   any a; only the joint original-index relation is sufficient.
   Logit/temperature/selection schemas each have 10000-configuration exact
   column/framing checks and full small-vector arithmetic. Temperature cases
   retain request-domain failures and nonmaximum logits rounded to zero.
   The full 1048576-token boundary preserves its empty CDF bucket and final
   endpoint 2^32. All original weight, permutation/inverse, prefix, minimal
   top-p, retained-divisor and selected-bucket joins remain required consumers.
   Schema 18 covers request length, stop membership, absolute positions and
   original token-byte indices with shape-derived bounds. Full-domain request
   and token-I/O frames retain context/vocabulary 2^20. The EOS public-mask
   formula matches independent dense folding at 10000 M31 points; native E6
   source construction and all challenge-field/profile parity remain required.
   The full model still needs Artifact/source/view indexing and actual
   consuming-reduction closure. No generic opaque certificate or
   caller-selected field is accepted.
   Model parsing retains full configured domains without deriving a certificate
   or weakening static admission based on sampled values.
   Full-domain Scales retains all 16777216 channels; no observed code or
   activation is used to tighten bounds. Collection derivation retains the
   complete Scales hash even when a changed channel leaves its maximum unchanged.
   Registry's derived manifest and total metadata bounds fit 256 KiB and 1 MiB.
   Its data regeneration is mandatory even when all metadata parses; this step
   still does not establish score/full-block or other arithmetic admission.
   Physical schema 19 uses only Shape and Model-selected formats. Its five-byte
   indices cover N=2^34; all 10000 records match independent polynomial/struct
   derivation, with complete actual-word column checks. Every named/maximal
   physical role is retained. The whole record is statically below 36000 bytes.
   Collection parameters come from full declared domains and complete checked
   scale entries. A maximum channel mantissa bounds arithmetic; every original
   channel still participates in Scales identity and its actual source consumer.
   All 10000 independently expanded parameter sets agree. Twenty-two complete
   frames and every named/maximal record match independent byte oracles.
7. **Padding and masks.** Source records have exact shapes and no matrix-row
   padding; int4 has only its odd final high nibble. Attention retains absolute
   positions and blocks. The maximum record retains every dense real key, the
   causal mask, first tie and canonical masked delta/gap/index zeros; actual
   masked scores still require their source/arithmetic checks. Actual lookup/zerocheck selectors and public-source MLE
   layouts remain proof-plan requirements. Raw coefficient data/zero padding is
   not proof that padded rows are excluded.
   Exp components retain real-row membership separately from canonical table
   padding. Masked values/remainders/corrections are zero. Activation operation
   padding has zero source words and a disabled lookup, not a real sigmoid(0)
   evaluation. The original selector and actual input/output joins remain.
   Weighted cases retain complete real/masked/padded key spans and all absolute
   block ids. A block rounded to zero retains its raw/source/remainder work.
   RMSNorm counts exactly d original statistic terms; inactive source words
   stay zero. Neither padded reciprocal rows nor padded exponent selections
   may become real queries. The row-wide M/J and factors retain their sources.
   Decoding excludes padding from every original maximum/permutation/prefix
   relation. Its inactive CDF words are zero for real unretained ranks, whose
   original prefix and weight checks remain active. Padded layouts gate complete
   equations, including constants; an output selector alone is insufficient.
   EOS membership excludes prompt/final/padded positions from the no-earlier-EOS
   sum. The last generated membership determines the reason, including coincidence
   with the token limit; an empty continuation cannot inherit prompt EOS.
   Model physical shapes come from Shape's closed role expansion, never supplied
   dimensions or padding. Rotation data and public-MLE masks remain unchecked here.
   Scales has one word per real matrix output channel and no padding entries.
   Registry regenerates real table rows and zero padding. Rotation data has
   exactly length*width/2 real pairs and no padding. Public-MLE selectors remain
   separately required at actual proof consumers.
   Physical int4 has no row padding; only the odd final high nibble is zero.
   Whole index range excludes that lane. Both source nibbles remain bound to
   the original byte; vector absence removes all matrix scale fields/roles.
   Every expected collection slot survives even when record parameters repeat.
   Request-dependent geometry and source selectors are not derived from a
   supplied collection count or from the static context capacity alone.
8. **Determinism.** Role/operation order, fused Q/K/V parts, UTF-8 ordering,
   physical payload order, rational encodings, function/representation selection,
   rounding, top-p ties and hash preimages are explicit. Source-map framing,
   raw transforms and the new static records match independent algorithms.
   Extracting the private shared encoder preserves the complete derivation and
   serialization syntax trees, with nine boundary records checked independently.
   The radix extension separately preserves all nonhelper syntax and exactly
   specializes to the prior three helper bodies at the default eight bits.
   Sixteen boundary encodings cover all earlier eleven schemas unchanged.
   Decoding record validation rejects changed bytes, truncated/suffixed frames
   and different valid expected parameters. The arithmetic seed is fixed; the
   existing selection/temperature and shared bound helpers remain unchanged.
   Complete Model framing now matches independent struct and function-component
   assembly on 10000 configurations. Scales independently matches another 10000
   complete frames and both maximal domains. Registry derives sorted unique
   definitions and preserves every ordered function/layer reference. Digest
   caches contain only regenerated data; rotation parameters validate before
   lookup so Boolean fields cannot alias integer keys. Artifact/passport codecs
   and full/cache model flows still need their checks.
   Registry's final run matches 15 complete component and 53 complete rotation
   definitions against independent real-data oracles. Expanded tests exposed a
   floor-versus-rounding error in the new oracle; it is corrected with a retained
   regression. The unchanged candidate follows RFC-0021's floor semantics.
   Physical role order and packed addresses follow the canonical Artifact
   layout, with no alternate vector or tied-head record selection.
   The collection's closed expansion selects all fractions/policies/matrices,
   derives Maximum's bound from Score and retains Normalize's exact Weighted
   parameters. It has no caller-selected role list or hash-only Registry path.
9. **Parity.** No CPU/SIMD/CUDA proof parity is claimed. The evidence is exact
   Python arithmetic and independent framing/coordinate/rational oracles. No
   named checkpoint is run by these checkers; named metadata cases only expand
   all roles. The original Rust/NumPy 10000-case per-op gates and full GPT-2-small/
   Llama-3.1-8B parity remain required implementation work.
   The complete 196/291-record Model fixtures use randomized numerical settings;
   they do not establish named presets or checkpoint fidelity.
   Named-shape Scales fixtures use patterned values without source conversion.
   Registry's named/maximal metadata layouts do not regenerate full named-model
   coefficient data or establish native/fidelity parity.
   All-role physical boundary checks likewise use metadata and coordinate words,
   without checkpoint payloads or a full-model execution.
   Named/maximal collection fixtures likewise derive complete record sets only;
   they do not regenerate named Registry data or execute checkpoint inference.
10. **Cost.** No constant moves and no benchmark is reported. New norm/bias/
    position/decoding work contributes T_witness/c_a/c_lu/T_misc as specified.
    Sampling explicitly charges vocabulary sorting and prefix work. Preparation
    scans are separate from the preserved one online physical-weight pass; a
    tied embedding/head still needs a single-source plan. No extra cut is granted.
    Model metadata parsing makes no weight-pass or runtime cost claim.
    Scales validation reports domain sizes only, with no benchmark claim.
    Registry generation contributes preparation T_misc for every selected table
    and rotation entry. Streaming its hash makes no measured speed claim.
    Physical bound derivation is T_misc; actual byte/source consumers remain
    charged to their reductions. No constant, weight pass or cut changes.
    Collection generation is preparation T_misc. Its stream does not alter
    the actual E7 weight schedule or establish a runtime speed claim.
11. **Verifier/resources.** Native no_std verifier code is unchanged. Metadata
    lengths/counts and source/scale domains are proposed explicitly; public scale
    data has a separate capacity bound from Model. Research retains Python arrays
    and is not evidence for fallible streaming, full-model memory or hostile
    proof parsing. The named models cannot inherit the old research size caps.
    Request counts and exact lengths precede entry materialization. Canonical
    TokenIO may remain a private hash preimage; commitment-mode tokens still
    require their own typed openings and same-source proof. The research parser
    receives plaintext expected prompt data and supplies no privacy evidence.
    Model's analytic bound is below 220000 bytes, with a 1 MiB cap and bounded
    inner frames. Full 128-layer fixtures parse without tensor payloads; this
    does not establish native fallible allocation or streaming behavior.
    Scales derives exact byte length before entry parsing and uses a separate
    64 MiB cap. Its full domain reaches 33558078 bytes; native allocation and
    RFC-0011's encrypted-to-verifiers scale policy remain unchanged obligations.
    Registry checks exact length and all expected metadata before regenerating
    data. Rotation rows are at most 32768 bytes, with no whole-table size cap.
    The bounded Python cache is not a native admission or resource guarantee.
    Physical records retain five-byte addresses and complete parameter-derived
    lengths; no tensor payload allocation is required for their derivation.
    The collection has at most 5005/4620 slots and a domain bound below
    496000000 bytes, within 512 MiB. A record stream or incremental digest is
    complete only after exhaustion; early prefixes confer no admission.
12. **Glossary.** The draft passes the repository glossary gate. It retains the
    distinctions between numerical metadata, bound certificate, claim, source,
    plan, passport, profile and full inference proof.
    Structural Model identity remains distinct from full cqis_id and admission.
    Legal scale values remain distinct from authenticated conversion results.
    Regenerated Registry data remains distinct from authenticated proof sources.
    A physical address or range certificate is not a source-ownership handle.
    Complete numerical Bounds remains distinct from a complete proof plan,
    authenticated passport or accepted inference statement.

I tried to break it by changing a fused Q/K/V part, omitting a required role and
changing one byte of the tied-head alias, and the source-map controls rejected it.
That result is limited to the research mapper and does not approve a protocol.

## Findings still preventing acceptance

Actual consuming-reduction closure, authenticated outer
passport/request schemas, independent artifact/passport codecs,
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
