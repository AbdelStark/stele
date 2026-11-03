# E5-03b — Full-model CQIS draft review

Decision: retain Draft; E5-03b remains in progress. This is a checkpoint of the
contract and evidence, not approval to merge or instantiate production behavior.
The same author, codex-root, applies rfc-author, cqis-numerics, gkr-reduction-author
and soundness-auditor. No independent human or agent review is claimed.

Scope: [RFC-0025](../../docs/rfcs/RFC-0025-full-model-cqis.md), its encoding and
decoding/static-arithmetic/consumer appendices, coordinated Draft additions to RFC-0001/0004/0011/0017/0021, and
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
   Encoding §3 now closes Preparation and streaming Artifact parsing. RFC-0011
   A4 proposes their passport/commitment binding while preserving Accepted text.
   The source appendix now specifies complete typed Source/Assets frames and
   original-byte container/selection checks, under Draft RFC-0011 A3/A4.

   The conversion appendix now specifies exact original-scalar access and
   exact Scales derivation and streamed Artifact emission under RFC-0025 §2.1.

   The source-architecture appendix adds three explicit HF source layouts and
   the canonical SourceConfig binding, under Draft RFC-0011 A3/A4.

   Decoding execution composes the existing Model/RequestBoundary definitions,
   selected exponential representation and seed/absolute-position rules. No new
   numerical policy or independently accepted protocol is introduced.

   The execution appendix composes both complete numerical model families from
   canonical Artifact bytes, under the existing Draft RFC-0025 definitions.

   Preparation now joins those existing source/config/conversion/Artifact
   contracts before numerical execution. The numerical identity implements the
   existing encoding §6 preimage with complete collection validation.

   The public-input appendix specifies the complete envelope with Draft
   RFC-0001 A2, RFC-0005 A4, RFC-0011 A5 and RFC-0016 A2. These append-only
   proposals distinguish the passport template from the per-request plan
   instance; all child codecs remain mandatory.

   The passport-composition appendix and Draft RFC-0011 A6/RFC-0016 A3 define
   subject/evidence/registration/signature framing and exact preimages. Child
   codecs, approved signature suites/authority and private proof validation
   remain mandatory; outer syntax admits none of them.

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
   Artifact digest comparison also requires an independently expected value;
   complete byte hashing cannot authenticate its own source or passport.
   Source and Assets identities also require independent expected authority.
   The complete Source frame remains bound even when a kind-0 filename change
   leaves its single-file SHA-256 unchanged.

   Conversion adds no challenge. Its emitted-byte digest and source identities
   still require the complete authenticated passport and H/query schedule.

   SourceConfig binds complete Model/Map/Assets hashes and the derived source
   architecture. These expected inputs still require passport authority; the
   deterministic binding adds no Fiat–Shamir challenge.

   The composition derives the existing seed/draw preimages. It accepts no
   caller-supplied draw; these deterministic hashes retain their required wrapper
   proof and accounting and do not become Transcript challenges.

   Full/cache execution adds no challenge or hash domain. Cache scope retains
   Model/Scales/Artifact identities as internal state, without protocol authority.

   The 152-byte numerical identity is rederived from complete expected
   Model/Scales/Registry/Bounds. It authenticates no publisher or supplied
   expected value and introduces no hash domain or challenge.

   Full public bytes reach the existing constructor absorb once, only after
   actual passport/plan/ledger/profile validation. The research codec
   constructs no transcript and grants no authority to supplied roots or
   profile tags.

   Composition adds deterministic reference and identity preimages, with no
   Fiat-Shamir challenge or transcript construction. Actual evidence proofs
   must bind the pre-evidence subject and same original sources; signatures
   cover the defined earlier identities, not the later final root.

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
   The Artifact codec retains exact record/scale/payload association. Source
   regeneration and actual commitment-to-Artifact hash consumers remain required.
   Source verification returns immutable original-byte slices after all files,
   shard locations, selection metadata and permitted alias bytes pass. It does
   not create an E6 source handle or discharge conversion/text-adapter semantics.

   Numerical conversion consumes verified immutable source slices and derives
   every scale/code byte. The resulting metadata cannot construct a native
   source handle or prove what a separate storage system or commitment contains.

   The config adapter checks original numeric fields and every physical role
   name/transform. Its result cannot authorize an E6 source, tokenizer, decoding
   policy or proof; those actual consumers retain their complete joins.

   Sampling now consumes the actual configured exponential point values before
   top-p/CDF selection. Previous-position logits and original seed remain
   numerical inputs whose native source/commitment relations must still be proven.

   Every numerical projection now reads original Artifact codes/scales and the
   declared physical role. Source/commitment provenance, Registry/Bounds admission
   and authenticated outer consumers remain required for a native proof.

   The same original-file snapshot, Model/Map/Assets and derived Scales reach
   stored-byte validation and execution. Complete collection validation
   supplies numerical identity evidence only; native source and commitment
   consumers remain required.

   Public g/reason must reach the same original TokenIO or plan-owned committed
   prompt/output sources, causal/decode selectors and stop/inference consumers.
   Plan/ledger reference bytes do not supply those consumers or a private
   opening.

   The source helper regenerates complete conversion, stored Artifact,
   numerical identity and eight subject references from the same original
   files. Plan/weight/table references and all evidence/key/signature
   references still require their complete actual validators and authority.

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
   Artifact controls target configuration/scale/length substitution, malformed
   reads, excluded codes, odd packed tails and changed canonical payload hashes.
   All 10000 byte mutations reject: 7352 structurally and 2648 at expected
   digest identity. Bad codes beyond the stream chunk boundary reject as well.
   Source controls reject file/hash/index/selection/alias changes, malformed
   containers and mutable inputs. Canonical index whitespace or partition
   changes alter the bundle identity even when selected tensor bytes agree.
   These are research controls, with no native NC coverage.

   Conversion controls include selected nonfinite values, int16 halfway
   overflow, late fused-partition failures, file changes and failed output
   writes. All selected scalar checks precede output; no native NC credit follows.

   SourceConfig controls reject changed shape/epsilon/rotation/layout, wrong
   source roles, ignored nonbuffers, unsupported flags and hostile JSON. A
   metadata-only file change preserves architecture but changes the binding.

   Composition controls reject changed policy/seed, mismatched prompt, generated
   EOS already in the prefix, exhausted limits, bad logits and exp-domain failure.
   The zero-limit sampled seed check remains explicit and mandatory.

   Execution controls cover Artifact substitution, cache scope, static score/block
   admission, odd int4 indexing and failure before exposing new cache state. A
   selected EOS must finish evaluation before successful stopping.

   Integration controls reject changed config/source bytes, missing or mutable
   assets, rehashed epsilon substitution and wrong physical roles. Identity
   controls reject altered fields, malformed frames, stale Model and corrupted
   complete Registry/Bounds; none earns native NC credit.

   Public-envelope controls reject altered expected
   identity/profile/policy/geometry/I/O fields, malformed counts/tags, field-
   congruent lengths, duplicate tree references and changed digest preimages.
   Actual statement/profile/passport/source controls remain required; research
   checks earn no native NC credit.

   Controls reject stale embedded subject/evidence identities, wrong signer
   roster/order, malformed references, altered expected frames and substitution
   of subject_id for final passport_root in the public input. These
   structural/research checks do not verify signatures or certificates and earn
   no native NC credit.

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
   Preparation/Artifact identities instantiate no native H/query schedule here.
   Source/Assets SHA-256 and BLAKE3 uses remain part of the pending complete
   identity accounting; this research codec adds no native loss or query line.

   Exact source conversion adds deterministic arithmetic and hash uses only;
   the required global identity accounting is unchanged acceptance work.

   SourceConfig adds research content-hash uses only. Their complete native
   H/query schedule remains part of the coordinated accounting amendment.

   No hash domain or native query budget changes. The existing seed and per-token
   draw hashes still need their actual consumer schedule in the global ledger.

   No native accounting line is discharged by numerical execution. All original
   identity, seed/draw, source and reduction consumers retain their ledger work.

   Composition reuses existing SourceConfig/conversion/Artifact and numerical
   identity hashes. No native query or loss line is added or discharged;
   complete passport and wrapper accounting remains required.

   No new challenge, extra absorb or native loss line is introduced.
   Plan/ledger/TokenIO/numerical hashes still require their complete actual
   H/query accounting, and a profile tag never satisfies the security budget.

   New reference/composition and eventual signature-suite hash uses retain
   explicit complete H/query obligations. No native ledger line or profile is
   enabled; honest metadata counts cannot substitute for adversarial/quantum
   accounting.

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
   The full model still needs actual Artifact/source/view indexing consumers
   and consuming-reduction closure. No generic opaque certificate or
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
   Complete Artifact lengths and global record/payload offsets derive from all
   Model dimensions/formats with checked u64 arithmetic and a bound below 2^39.
   All named/maximal layout offsets match independent derivation; the largest
   Artifact is 274919947094 bytes without allocating its weight payloads.
   Source file lengths, aggregate lengths and tensor offsets retain checked
   u64 values. Index length bounds shard count and total filename bytes before
   descriptor allocation; the frame cap is independent of checkpoint payloads.

   Minimal matrix exponents/mantissas derive from all transformed source
   values. They do not use rounded codes to tighten static bounds.
   Every original scalar, full source index and int16 overflow rule is retained.

   Exact decimal rationals preserve config epsilon and rotation values; no
   binary64 cast or observed tensor range tightens bounds. The adapter retains
   full shapes and checks every layer against the same source architecture.

   The existing logit/temperature/exp/sampling/request bounds govern composition.
   Complete vocabulary and absolute-position domains remain intact; numerical
   success never tightens a static certificate or admits the rest of the model.

   Static score and full-1024-slot block bounds are checked before inference.
   Every configured unit, scale and exact gated product remains intact; generic
   execution does not construct a complete native bound-certificate consumer.

   Identity generation validates the complete statically derived collection
   under the same Model/Scales/Registry. Original-source numerical failures
   remain rejections and cannot tighten any declared bound.

   N=q+g selects actual request geometry; Model context n remains the bound
   capacity. The public frame cannot tighten any static bound using observed
   tokens, lengths or numerical results.

   Fixed subject roles and bounded roster counts determine outer lengths.
   Referenced u64 lengths never allocate child payloads or tighten arithmetic
   Bounds; actual child validators retain their independent shape/resource and
   static-domain checks.

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
   Artifact payloads have no per-row int4 padding; an odd final high nibble is
   zero. Both real nibbles and all int8 bytes retain symmetric code ranges.
   Source containers require dense exact coverage, including ignored tensors.
   Their allowed raw scalar/empty/sub-byte formats do not change the selected
   physical role shapes, packed Artifact tails or permitted alias rules.

   Conversion emits continuous physical-order int4 nibbles across odd rows,
   with only the final inactive nibble zero. This does not admit proof padding
   selectors or substitute for committed source geometry.

   Recognized legacy mask/frequency buffers remain excluded from execution.
   They cannot replace configured causal masks, regenerated rotary data or any
   required physical source; full container coverage still applies to them.

   All vocabulary ids reach selection; the full permutation retains zero masses.
   Prompt EOS is excluded from stop checks, and generated-prefix EOS prevents
   another choice. Actual padded native sources remain separate obligations.

   Full and cached attention retain absolute block boundaries and masked zeros.
   Whole-row conversions precede head/group views and follow concatenation;
   learned positions and rotary data remain distinct source roles.

   Source-to-execution composition preserves the existing fused partitions,
   physical order, packed tails and absolute causal positions. It introduces no
   padding rule or new cut.

   Generated positions remain q through N-1, with previous-logit positions q-1
   through N-2. Zero continuation removes decode rows but retains prompt
   evaluation and seed binding. A committed empty output still needs its
   complete canonical source contract.

   Only the two defined optional references have presence tags. All-zero
   digests remain ordinary present values. No source padding, private layout,
   mask lifecycle or intermediate commitment is introduced by the envelope.

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
   lookup so Boolean fields cannot alias integer keys. Complete passport
   codecs, native source regeneration and full/cache model flows still need
   their checks.
   Registry's final run matches 15 complete component and 53 complete rotation
   definitions against independent real-data oracles. Expanded tests exposed a
   floor-versus-rounding error in the new oracle; it is corrected with a retained
   regression. The unchanged candidate follows RFC-0021's floor semantics.
   Physical role order and packed addresses follow the canonical Artifact
   layout, with no alternate vector or tied-head record selection.
   The collection's closed expansion selects all fractions/policies/matrices,
   derives Maximum's bound from Score and retains Normalize's exact Weighted
   parameters. It has no caller-selected role list or hash-only Registry path.
   Preparation binds the exact Map and physical C_i, independently of unrelated
   runtime fractions. Artifact includes every exact configured scale/payload byte.
   Source/Assets frames preserve exact UTF-8 names and original file bytes.
   Returned slices keep the immutable bytes whose hashes passed; dictionary
   replacement cannot substitute data after verification. Native source conversion
   and complete passport/cache flows still require their own evidence.

   Conversion uses integer dyadic comparisons and exact signed half-away
   division. Fused Q/K/V matrices derive separate scales. Source repartitioning
   and signed-zero representations can preserve Artifact while changing Source.

   Layout tags distinguish bare/prefixed GPT-2 names and HF split-half Llama
   channels. Closed absence rules, exact JSON numbers and canonical semantic
   frames match independent config/role/struct oracles on 10000 configurations.

   Absolute prefix length determines the draw position. Greedy ties choose the
   first maximum; sampled ties/order and CDF boundaries use the existing exact
   rules. Certified point caches contain only definition-derived values.

   Complete residual cuts, logits and K/V prefixes are compared across batch
   and append evaluation. Both FFNs, affine biases and fractional alignments use
   the same explicit Model; generation evaluates the final EOS.

   All 36 original packages match independent conversion bytes and execution
   outcomes. The activation oracle now uses the strict mathematical magnitude
   bound at saturation; candidate execution is unchanged, and the old checker
   is retained for evidence.

   PublicInput has fixed field order and lengths, complete policy bytes, closed
   I/O modes and exact exhaustion. Passport template and request instance
   identities remain distinct; the plan excludes its own hash and outer
   roots/ledger digest to avoid cycles.

   The exact order is subject, evidence, registration, signatures and final
   root. Keys are strictly sorted by complete descriptor digest; signatures
   match that roster exactly. Later registry receipts remain external, and
   changing a signature changes the root without changing its own signed
   message.

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
   Artifact layout fixtures likewise retain full shapes without allocating
   named weight payloads or claiming source conversion/fidelity/native parity.
   Source containers are compared with pinned safetensors 0.6.2 decoding.
   The large generated source fixture is not a named checkpoint, native parity
   or a model-fidelity result.

   Conversion uses independent rational scalar/transform/framing checks and
   the unchanged quantiser helper as its oracle. The large generated conversion
   fixture is neither a named checkpoint nor Rust/SIMD/CUDA parity evidence.

   The actual GPT-2 config and header match all 196 physical roles across
   148 selected tensors and 12 legacy buffers. This is header metadata only.
   The gated Llama config returned HTTP 401. Its named-shape fixture uses pinned
   Meta architecture and cannot establish checkpoint compatibility or fidelity.

   The new composition checker compares rational temperature arithmetic, Arb
   exponential values and independent CDF intervals. This remains numerical
   research, without Rust/NumPy, full model/cache or named-fidelity credit.

   The new oracle uses independent rational/Arb arithmetic for complete models
   and generation. Large addressing is exercised without named-model fidelity,
   Rust/NumPy, native proof or GPU parity credit.

   Generic two-layer original-source fixtures cover three layouts, four IEEE
   formats and one to three shards. Their exact checks and complete
   Registry/Bounds identities provide no named-fidelity, native, proof or GPU
   parity credit.

   The new evidence checks structural envelope bytes and plaintext TokenIO
   joins, with two complete numerical identity joins. Commitment references and
   profile tags are fixtures, not private PCS/ZK, native inference, named
   fidelity or admitted-profile evidence.

   Composition checks use structural evidence/key/signature reference fixtures,
   without cryptographic verification. Two original-source numerical joins and
   full reference-count framing establish no named fidelity, native proof,
   private PCS/ZK or parity result.

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
    Artifact syntax validation scans its complete bytes during preparation;
    it does not alter the one-pass inference schedule or wrapper hash obligation.
    Source hashing/parsing is preparation T_misc. The index is grouped once
    by shard; this supplies no measured speed result or online weight-pass change.

    Conversion uses two offline matrix scans for scales and one for emitted
    codes; vector validation and emission are separate. These preparation
    scans do not change the one online weight pass or report a measured constant.

    Source architecture parsing and role comparison are preparation T_misc.
    No inference weight pass, cost constant or measured performance claim changes.

    Decoding retains its O(v log v) sorting and O(v) arithmetic/storage costs;
    prefix validation costs O(n). This introduces no weight pass or measured
    constant. Point certificates are research work, not a native performance claim.

    Numerical execution retains full Artifact bytes and O(Nv+NLd) batch arrays.
    This is research resource behavior, without a measured constant or change
    to the one online weight pass required of the prover.

    Preparation retains original and complete converted bytes, with a separate
    stored-Artifact validation scan. These offline costs do not change the
    online proof weight-pass requirement or report a measured constant.

    Envelope parsing, existing identity hashes and deterministic geometry
    contribute T_misc. No measured constant, new cut or online weight-pass
    change is claimed; complete native proof and private-source costs remain
    required.

    Content hashing, evidence and signature verification remain explicit
    preparation/T_misc/registration work. No measured constant, extra online
    weight pass or native performance improvement is claimed.

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
    Preparation has a separate 17 MiB cap. Artifact reads use at most 64 KiB
    chunks and expected lengths, with short reads supported and exact EOF.
    A supplied u64 length never controls allocation. Native streaming and
    resource admission still require their own implementation qualification.
    The 16 MiB Map boundary round-trips, and complete Artifact bytes/hashes
    agree under three-byte short reads and payloads crossing 64 KiB chunks.
    Source retains complete immutable input files and returns read-only slices
    without whole-tensor copies. This is not native bounded-memory admission.
    Native loading must preserve the same bytes through every consuming pass.

    Conversion retains source files and bounded Scales metadata, reads scalar
    spans and emits chunks of at most 65536 bytes. Failed writes produce no
    success result; partial output must be discarded. Native resource admission
    and stored-byte integrity still require their own checks.

    Config JSON has explicit byte/node/depth/string/number bounds. The parser
    checks pending-node capacity before expanding children; complete binding
    verification derives expected bytes. Native fallible parsing remains required.

    The public policy has an analytic frame cap. Research retains complete
    vocabulary arrays and a bounded derived-point cache; native fallible resources
    and the complete Registry still require validation. Failure returns no Decision.

    Internal immutable caches are execution state. Structural validation cannot
    authenticate caller-forged K/V provenance; native fallible allocation and
    source/state proof consumers remain required.

    Prepared is a research numerical result, not a native admission handle.
    Complete source/output bytes remain resident; publisher authority, native
    fallible allocation and private commitment/proof resources are still
    separate requirements.

    The frame has a domain bound of 4194976 bytes and an 8 MiB cap. Expected
    Model/request policy determines length before payload access. Native
    no_std/fallible parsing, complete passport/plan/ledger validation and
    private source resources remain implementation requirements.

    The maximal outer frame is 7340889 bytes for 65535 keys, within 8 MiB; the
    message is 120 bytes. Child lengths and counts exhaust exact sections before
    entry construction. Native fallible allocation/streaming and complete child
    admission remain required.

12. **Glossary.** The draft passes the repository glossary gate. It retains the
    distinctions between numerical metadata, bound certificate, claim, source,
    plan, passport, profile and full inference proof.
    Structural Model identity remains distinct from full cqis_id and admission.
    Legal scale values remain distinct from authenticated conversion results.
    Regenerated Registry data remains distinct from authenticated proof sources.
    A physical address or range certificate is not a source-ownership handle.
    Complete numerical Bounds remains distinct from a complete proof plan,
    authenticated passport or accepted inference statement.
    A structurally valid Artifact remains distinct from reproducible conversion
    and the proven binding between committed plaintext and digest_cqis.

    A typed file identity or Assets digest remains distinct from publisher
    authority, semantic configuration/tokenizer validation and a proof source.

    A numerical conversion result remains distinct from a proven source,
    committed-plaintext hash binding, semantic adapter or complete passport.

    SourceConfig establishes a declared architecture/role binding only. It
    remains distinct from tokenizer behavior, source publisher authority and
    a full passport or native proof source.

    A Decision is numerical evidence. Policy bytes bind the decoding/request
    subrecord only; the complete Model identity, original token/logit sources,
    private seed and outer authenticated statement remain distinct requirements.

    Numerical Data, Full, Step and Cache values are not proof-admission handles.
    Artifact syntax/digest checks remain distinct from publisher authority,
    private commitments, full passport verification and named fidelity.

    Prepared and the numerical identity preimage remain research values. Their
    complete validation is distinct from an authenticated passport, public input,
    private commitment or accepted native proof.

    Public Fields and CommittedIO contain structural reference data. They
    remain distinct from an admitted passport, plan, private source, security
    profile and verified inference statement.

    Subject, Evidence, Registration and Signature values are metadata. A
    signature reference differs from a verified signature; subject_id differs
    from the final passport_root carried by PublicInput. Neither root grants
    its own authority.


I tried to break it by changing a fused Q/K/V part, omitting a required role and
changing one byte of the tied-head alias, and the source-map controls rejected it.
That result is limited to the research mapper and does not approve a protocol.

I tried to break numerical execution by substituting Artifact bytes, reusing a
different cache scope and supplying inadmissible score/block parameters, and the
execution controls rejected it. This is research evidence, not native approval.

I tried to break preparation with rehashed wrong epsilon, altered source files
and substituted roles, and the controls rejected them. Corrupted complete
Registry/Bounds and identity frames also rejected. These are numerical research
checks; E5-03b remains Draft/in_progress.

I tried to break the public envelope with altered profile/identity/policy fields,
field-congruent lengths, duplicate tree references and changed token preimages;
the research controls rejected them. This does not approve native proof admission.

I tried to break composition with stale evidence subjects, altered registration
evidence, wrong signers and a subject-id substitution for the final public root;
the research controls rejected them. Signature/proof admission remains unimplemented.

## Findings still preventing acceptance

Actual consuming-reduction closure, authenticated outer
passport/request schemas, complete passport codecs, actual native conversion
consumers, actual named source/config admission and tokenizer/generation adapters,
native GPT-2/Llama full/cache execution, sampling's native exp/request/
seed source bindings, coordinated accounting/control amendments, and sequential native
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
