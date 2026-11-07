# Negative-control catalogue (INV-4). Every row is a test that must be *rejected* with the stated error.

| NC-id | Binding | RFC § | Tamper | Expected error | Status |
|---|---|---|---|---|---|
| NC-0001 | output token ↔ logits | 0004 §7 | flip one generated token | `DecodeMismatch` | todo |
| NC-0002 | residual cut ↔ layer | 0007 §3 | +1 on one `R_ℓ` element after capture | `ClaimMismatch(R_stack)` | todo |
| NC-0003 | weight block ↔ layer index | 0007 §2 | swap `W_Q` blocks of two layers | `FusedOpeningMismatch` | todo |
| NC-0004 | passport binding | 0011 | prove with another passport | `PassportRootMismatch` | todo |
| NC-0005 | prompt binding | 0001 §3 | change one prompt id in `io_digest` | `EmbeddingClaimMismatch` | todo |
| NC-0100–0109 | CQIS gadgets | 0004 §10 | see RFC | typed per gadget | todo |
| NC-0110 | LayerNorm | 0025 §2.3, 0021 A2 | change one norm kind to RMSNorm | `NormKindMismatch` | todo |
| NC-0111 | LayerNorm | 0025 §2.3 | replace one centered numerator with the value from a rounded mean | `LayerNormMeanMismatch` | todo |
| NC-0112 | LayerNorm | 0025 §2.3 | change one learned bias value under the original source | `NormBiasMismatch` | todo |
| NC-0113 | learned position | 0025 §2.5 | substitute one learned-position source handle | `PositionSourceMismatch` | todo |
| NC-0114 | learned position | 0025 §2.5 | change one absolute gather position | `PositionIndexMismatch` | todo |
| NC-0115 | affine projection | 0025 §2.2 | omit one nonzero original projection bias | `AffineBiasMismatch` | todo |
| NC-0116 | affine projection | 0025 §2.2 | replace one result with rounding before bias addition on a separating case | `AffineRoundingMismatch` | todo |
| NC-0117 | FFN family | 0025 §2.5 | select one activation role from the other model family | `FunctionMismatch` | todo |
| NC-0118 | physical roles | 0025 §2.7 | omit one required physical role | `PhysicalRoleMismatch` | todo |
| NC-0119 | physical roles | 0025 §2.5 | replace the tied head source with a separately committed equal-valued tensor | `TiedSourceMismatch` | todo |
| NC-0120 | numerical identity | 0025 §2.7 | change one Model parameter while retaining the independently expected cqis_id | `CqisIdentityMismatch` | todo |
| NC-0121 | source configuration | 0025 §2.7, 0011 A7 | change one original architecture field while retaining the expected Model | `SourceConfigMismatch` | todo |
| NC-0122 | gated scale | 0025 §2.5, 0003 A4 | truncate one valid gated scale above 65535 to its low u16 | `ScaleSourceMismatch` | todo |
| NC-0123 | attention row scope | 0025 §2.4, 0009 A3 | substitute one head-local scale for the original complete-row scale | `RowScopeMismatch` | todo |
| NC-0124 | absolute blocks | 0025 §2.4, 0009 A3 | change one key's absolute block index | `BlockPositionMismatch` | todo |
| NC-0125 | request stop | 0025 §2.6 | change EOS reason to limit when EOS coincides with maximum_new | `StopMismatch` | todo |
| NC-0126 | sampling position | 0025 §2.6 | derive one draw at another absolute position under the same seed | `DrawPositionMismatch` | todo |
| NC-0127 | wide residual width | 0004 A14 | select rmsnorm_q version 1 for one norm of a version-2 Model | `Width` | todo |
| NC-0128 | wide residual target | 0004 A14 | set one schema-22 aligned output to 2^23 | `WideRange` | todo |
| NC-0129 | residual width substitution | 0004 A14 | check one int24 source with an int16-only decomposition, or admit an int24 norm output | `WidthMismatch` | todo |
| NC-0130 | wide norm gain source | 0004 A14, 0021 A4 | bind the int16 gain through the int24 X roles 1/2 instead of roles 27/28 | `SourceMismatch` | todo |
| NC-0131 | grouped row scale | 0004 A15 | derive one group's scale from another group's or the whole row's attained maximum | `GroupScaleMismatch` | todo |
| NC-0132 | grouped row partition | 0004 A15 | consume the first code of a group with the preceding group's scale | `GroupPartitionMismatch` | todo |
| NC-0133 | grouped fold | 0004 A15 | change one fold F = s*abs(q) by one with digits recomposing the changed value | `FoldMismatch` | todo |
| NC-0134 | grouped digits | 0004 A15, 0007 A6 | replace the gated fold X's digits by the in-range alias (124,0,0,-64) of X-p, or flip one fold sign bit | `FoldSignMismatch` | todo |
| NC-0135 | grouped recombination | 0004 A15, 0007 A6 | replace one U_t by U_t + p, with valid bytes and the same residue, so the sign join balances at A' + p; the top-byte cap must reject it | `AccumulatorRange` | todo |
| NC-0136 | grouped policy | 0004 A15, 0025 A2 | prove one grouped row under group size g/2 while retaining the expected Model and Bounds | `GroupSizeMismatch` | todo |
| NC-0200 | sumcheck engine | 0006 A1 | change one round evaluation | `RoundSumMismatch` | done |
| NC-0201 | sumcheck engine | 0006 A1 | one final evaluation folded at another instance's challenge | `FinalEvaluationMismatch` | done |
| NC-0202 | sumcheck engine | 0006 A2 | omit one member/claim contribution from one round evaluation | `RoundSumMismatch` | done |
| NC-0203 | stacked coefficient | 0006 A4 | one coefficient final evaluated at the wrong layer; empty P preserves the A1 check | `CoefficientMismatch` | done |
| NC-0204 | sumcheck engine | 0006 A5 | small strategy on a truncated unused original value; one changed final | `ClaimMismatch` | done |
| NC-0205 | sumcheck engine | 0006 A1,A2 | unused final under constant P; mode 1 changes one unclaimed tensor entry | `ClaimMismatch` | done |
| NC-0206 | sumcheck engine | 0006 A2, 0012 A4 | one round evaluation computed with coefficient drawn before Batch | `RoundSumMismatch` | done |
| NC-0207 | sumcheck engine | 0006 A3 | change one skip evaluation or compute it with an early weight | `RoundSumMismatch / FinalEvaluationMismatch` | done |
| NC-0208 | sumcheck engine | 0006 A3 | change one weighted tail endpoint or compute it with an early skip challenge | `RoundSumMismatch` | done |
| NC-0209 | sumcheck engine | 0006 A3 | change one unused original slice final | `ClaimMismatch` | done |
| NC-0210 | sumcheck engine | 0006 A6 | change one unused Streaming source value; one changed final under original consumer | `ClaimMismatch` | done |
| NC-0211 | stacked canonical point | 0006 A4 | one unused original final from the raw layer-last point | `ClaimMismatch / ValueMismatch` | done |
| NC-0212 | stacked public coefficient source | 0006 A4 | one coefficient final from a changed expected onehot/table value | `CoefficientMismatch` | done |
| NC-0213 | stacked original certificate | 0006 A4 | substitute one separately verified certificate for an unchanged original opening | `RootMismatch` | done |
| NC-0300–0305 | matmul phases | 0007 §8 | see RFC | | todo |
| NC-0306 | matmul phases | 0007 A2, 0024 §6 | one partial row uses a changed outer coordinate, fixed expected source and zero opposite factor | `ColumnMismatch` | done |
| NC-0307 | matmul phases | 0007 A2, 0024 §6 | change one original final under a zero opposite factor; keep its opening row | `ValueMismatch` | done |
| NC-0308 | Requant input bytes | 0023 §6 | field-congruent int32 substituted in advice/arithmetic | `ValueMismatch` | done |
| NC-0309 | Requant advice identity | 0023 §6 | separately verified advice handle under unchanged packet | `CertificateContext` | done |
| NC-0310 | Requant full-width result | 0023 §6 | t=65537 and q=1 retain valid low division columns | `FinalEvaluationMismatch` | done |
| NC-0311 | Requant carry | 0023 §6 | one interior carry exceeds its cap or changes a column | `FinalEvaluationMismatch` | done |
| NC-0312 | Requant plane mapping | 0023 §6, 0024 §6 | one producer group row uses the wrong plane, including the embedded output group | `ValueMismatch` | done |
| NC-0313 | Requant sign and target | 0023 §6 | s=1 at v=0 | `FinalEvaluationMismatch` | done |
| NC-0314 | Requant padding | 0023 §6, 0024 §6 | one padded or reserved-plane byte becomes one, including an embedded physical reserved plane | `RoundSumMismatch / FinalEvaluationMismatch` | done |
| NC-0315 | centered original bytes | 0024 §6 | one original byte256 under a zero opposite signed factor, fixed negative statement | `RootMismatch` | done |
| NC-0316 | centered accumulator cap | 0024 §6 | one new high-cap slack A3 final becomes one | `FinalEvaluationMismatch` | done |
| NC-0317 | centered matmul join | 0024 §6 | one scalar signed-matmul original final changes under nonzero opposite factor | `FinalEvaluationMismatch` | done |
| NC-0318 | centered affine source | 0024 §6 | one scalar raw opening-row cell replaced by its signed value | `ValueMismatch` | done |
| NC-0400 | lookups | 0008 §7,A5 | increment one multiplicity; rebuild actual registration and trees | `RootMismatch` | done |
| NC-0401 | lookups | 0008 §7,A5 | one selected source tuple outside the fixed table; truthful trees | `RootMismatch` | done |
| NC-0402 | lookups | 0008 §7,A5 | one inactive selector used as active by the prover under the unchanged expected selector | `SelectorMismatch` | done |
| NC-0403 | lookups | 0008 §7,A5 | second repetition's leaf arithmetic uses the first pair; actual outer draws remain independent | `TableDenominatorMismatch` | done |
| NC-0404–0405 | lookups | 0008 §7 | see RFC | `LogUpImbalance` etc. | todo |
| NC-0406 | fraction reduction | 0008 A3 | change one root numerator | `FinalEvaluationMismatch` | done |
| NC-0407 | fraction reduction | 0008 A3 | change one otherwise unused child final | `LeafMismatch` | done |
| NC-0408 | fraction reduction | 0008 A3 | change one equality final under zero products | `CoefficientMismatch` | done |
| NC-0409 | fraction reduction | 0008 A3 | change one selector final under zero products or one unused incoming tree child | `SelectorMismatch` | done |
| NC-0410 | fraction reduction | 0008 A3 | change one zero-coefficient source final | `SourceMismatch` | done |
| NC-0411 | fraction reduction | 0008 A3, 0012 A9 | one next-layer round value from Gamma before Fraction/Layer or Fold before Final | `RoundSumMismatch` | done |
| NC-0412 | configured function | 0021 §6, 0005 A1 | change one configured semantic parameter while retaining the original operation binding | `FunctionMismatch` | todo |
| NC-0413 | selected representation | 0021 §6, 0008 A4 | change one selected representation or component role | `RepresentationMismatch` | todo |
| NC-0414 | table data | 0021 §6, 0011 A2 | change one canonical table-data entry under the correct descriptor | `TableDataMismatch` | todo |
| NC-0415 | lookups | 0008 A5 | group exponent 31 exceeds the static characteristic bound | `GroupBound` | done |
| NC-0416 | lookups | 0008 A5 | one zero denominator leaf, with genuine dependent tree arithmetic | `Pole` | done |
| NC-0417 | lookups | 0008 A5 | change one multiplicity piece value under the actual unchanged table numerator | `PieceSumMismatch` | done |
| NC-0418 | lookups | 0008 A5 | substitute a verified different-root multiplicity handle under the unchanged registration packet | `CertificateContext` | done |
| NC-0419 | lookups | 0008 A5, 0012 A11 | one multiplicity fitted to an alpha drawn before its context binds | `RootMismatch` | done |
| NC-0420 | lookups | 0008 A2 | plan admission with m=3 and group exponent 2 instead of min(m,30)=3 | `GroupBound` | todo |
| NC-0421 | lookups | 0008 A2 | treaty plan admission with one repetition | `Statement` | todo |
| NC-0500–0506 | attention | 0009 §7 | see RFC | | todo |
| NC-0600 | PCS | 0010 A9 | change one certificate codeword limb or opening row value under zero b; rebuild dependent responses | `ColumnMismatch` | done |
| NC-0601 | PCS | 0010 A9 | replace one derived query index and its response/path, retaining all other draws | `RootMismatch` | done |
| NC-0602 | PCS | 0010 §10, 0012 A3 | wrong leaf payload or sibling for fixed root/index, both tree kinds | `RootMismatch` | done |
| NC-0603–0605 | PCS | 0010 §10 | see RFC | | todo |
| NC-0606 | PCS | 0010 A9, 0007 A2, 0023 §6, 0024 §6 | replace the expected certificate root or use a separately verified certificate for one unchanged opening; substitute one genuine Requant advice handle under its unchanged packet or one original range handle with responses from the old source | `RootMismatch / CertificateContext` | done |
| NC-0607 | PCS | 0010 A9 | authenticate a leaf containing the M31 modulus at the certificate and opening consumers, including zero a | `NoncanonicalField` | done |
| NC-0608 | PCS | 0010 A9 | after valid verification, import certificate bytes with one changed leaf; cached context cannot replace re-verification | `RootMismatch` | done |
| NC-0609 | PCS | 0010 A9 | change an unused RFC-0006 A1 final; regenerate preceding openings so rejection reaches its terminal source | `ValueMismatch` | done |
| NC-0610 | PCS | 0010 A9 §4, 0008 A5 §7, 0023 §6, 0024 §6 | change the expected scalar under zero b or one closed lookup mu-opening row value; replace one Requant or centered integer-linear source row using a swapped or omitted independent weight in each of four phases; reject before column draws | `ValueMismatch` | done |
| NC-0611 | PCS | 0010 A10, 0007 A2, 0024 §6 | one retained opening-row value changed, with dependent final/responses reconstructed under a zero opposite factor | `ColumnMismatch` | done |
| NC-0612 | PCS | 0010 A1, 0012 A7 | substitute a different v2 seed, Circle identity or evidence ID for the committed expander identity under the first actual expander PCS consumer | `CodeIdentityMismatch` | todo |
| NC-0700–0703 | passport | 0011 §6 | see RFC | | todo |
| NC-0704 | passport | 0011 A6/A7, 0025 §2.7 | alter one length or digest in each fixed child-reference role, one variant at a time | `ReferenceMismatch` | todo |
| NC-0705 | passport | 0011 A4/A7 | substitute one Preparation mapping under the original Artifact/source relation | `PreparationMismatch` | todo |
| NC-0706 | passport | 0011 A3/A7 | change the source-identity kind while retaining the digest bytes | `SourceIdentityMismatch` | todo |
| NC-0707 | passport | 0011 A7 | change one original config/tokenizer/generation asset byte under its expected File reference | `AssetsMismatch` | todo |
| NC-0708 | passport | 0011 A6, 0016 A3 | substitute one otherwise valid evidence child for a different subject | `EvidenceSubjectMismatch` | todo |
| NC-0709 | passport | 0011 A6 | substitute one signing key outside the independently expected registrant authority | `RegistrantMismatch` | todo |
| NC-0710 | passport | 0011 A6 | change one signature value under the unchanged signing message and key | `SignatureMismatch` | todo |
| NC-0800 | transcript/ledger | 0006 A1,A3, 0012 A1,A5 | one final evaluation folded at a challenge drawn before its round message | `FinalEvaluationMismatch` | done |
| NC-0801 | transcript/ledger | 0012 A1 | configuration: replace one registered label with another | `DuplicateLabel` | done |
| NC-0802 | transcript/ledger | 0006 A1,A2,A3,A4, 0008 A3,A5, 0010 A9, 0012 A1,A4,A5,A6,A9,A10,A11,A12,A13,A14, 0007 A2, 0024 §6 | next instance's one final value generated after omitting Final (including tree/selected-product), BatchFinal, ZeroFinal, OpeningColumns, Stack, StackSources, LookupStatement, LookupMultiplicities, LookupMultiplicityClaims, MatmulStatement either original matmul OpeningColumns, RequantStatement, RequantConstraints, each of three RequantClaims frames or final Requant OpeningColumns; centered LinearStatement, RequantConstraints, each RequantClaims or either original OpeningColumns | `FinalEvaluationMismatch` | done |
| NC-0803 | transcript/ledger | 0010 A9, 0012 A10 | replace one query with a differing index drawn before CertificateRow or OpeningRow absorption | `RootMismatch` | done |
| NC-0804–0805 | transcript/ledger | 0012 §6 | see RFC | | todo |
| NC-0900–0901 | ZK | 0013 §6 | see RFC | | todo |
| NC-1000–1002 | GPU | 0014 §7 | see RFC | | todo |
| NC-1100–1101 | distributed | 0015 §7 | see RFC | | todo |
| NC-1200–1203 | verifier/wrapper | 0016 §7 | see RFC | | todo |
| NC-1204 | request plan | 0005 A4, 0016 A2 | substitute one plan instance from a different request under the same model template | `PlanInstanceMismatch` | todo |
| NC-1205 | profile minimum | 0016 A2, 0025 §2.7 | change treaty to standard below the passport's minimum profile | `ProfileMismatch` | todo |
| NC-1206 | token source | 0016 A2, 0025 §2.6 | substitute one prompt/output source context while retaining the expected tokens and I/O mode | `TokenSourceMismatch` | todo |
Coverage report: `scripts/gates/negative-controls.sh --coverage` lists claim-graph edges, PCS checks and ledger lines without a control.

The RFC-0025 reservations NC-0110..0126, NC-0704..0710 and NC-1204..1206
remain `todo`. Their named errors are required rejection causes at the eventual
typed native consumers, not implemented error variants. The exact owner mapping
is RFC-0025 §6. Each reference-role variant retains full actual child validation;
outer byte comparison alone cannot earn a cryptographic source/evidence control.
These reservations add no coverage and change no existing control or registration.

The registry-collision entry checks the actual registry validator (configuration control, RFC-0012 A1). It does not establish a proof-statement binding. Early-challenge and missing-final-claim controls require real protocol consumers; primitive sensitivity tests earn no credit.

RFC-0010 A2 specifies a circle encoder only. Its research order/normalization and
distance counterexamples add no PCS binding or NC coverage. NC-0603..0605 still
require the actual commitment/opening consumers; E4-02 encoder tests cannot mark
them done or admit a PCS profile.

The public stacked runtime executes NC-0203, both source variants of NC-0212,
and both Stack/StackSources extensions of NC-0802 in QM31 and OM31.
The NC-0211 control also executes the certified variant: the unchanged opening reaches
ValueMismatch after Opening/OpeningRow and before any column query. NC-0213
substitutes one separately verified certificate for the unchanged original proof;
the actual opening rejects RootMismatch. Both fields retain the complete proof
bytes across that expected-context substitution. These conditional field controls
do not complete E3-06's resource evidence or admit inference/privacy profiles.

The conditional lookup runtime executes NC-0400..0403 and NC-0415..0419
through genuine registrations and the unchanged closed verifier in both fields.
The NC-0402 variant checks the unchanged literal selector; full CQIS
padding/range authority remains an E3-07 obligation. The lookup extensions of
the NC-0610 and NC-0802 controls execute the actual mu consumer and following A1 verifier.
They add composed coverage under those existing IDs, not extra controls or a
Fiat–Shamir theorem. Full private lookup and inference remain unadmitted.

The conditional matmul verifier executes NC-0306/0307/0611 for both original
sources in both fields. NC-0307 includes non-Boolean stacked layer/inner
restoration; W failures first consume X successfully. NC-0606 substitutes one
verified certificate through the complete consumer. NC-0802 independently omits
MatmulStatement, X OpeningColumns or W OpeningColumns, changing only a genuine
following A1 final. All accepted baselines use the same closed verifier. These
controls supply conditional field-relation coverage; full native production,
resource evidence, integer matmul and inference remain parent-task obligations.

The closed Requant verifier executes NC-0308..0314 in QM31 and OM31 with
fixed expected statements and actual A3/A9 consumers. NC-0313 covers s=1 at v=0
and positive q=H for both target formats. The positive-H candidates have only
the target residual +1 and reach actual A3 FinalEvaluationMismatch. NC-0314 covers reserved advice
planes and padded input/advice views. NC-0606 adds genuine advice-context
substitution; NC-0610 swaps or omits a weight independently in all four phases.
The NC-0802 cases omit six frames independently and change one following A1 final.
The scoped NC-0100/0101 cases exercise both signed rounding ties through A3;
The NC-0109 case checks the actual static bound encoding after an accepted baseline.
These do not complete the broad CQIS family or grant it catalog credit.
The native witness/producer is compared against unchanged independent full wires,
including full producer registration Usage and continuation. These 62 declared
variants include two static validations; they are not 62 proof rejections or new
catalog IDs. Complete operation resource evidence is separate from catalogue
coverage; inference/profile admission and the broad CQIS family remain parent work.

The centered integer-linear NC-0802 extension independently omits seven frames
for scalar and nonconstant stacked matrices, in both fields and both repetition
counts. Each accepted complete native producer matches the control composer
byte for byte. Each omission changes one following A1 final through ProverHook;
the unchanged closed operation accepts and the following A1 rejects with
FinalEvaluationMismatch and its exact observed prefix. These 56 variants add
coverage under NC-0802; they do not add catalog IDs or resource evidence.

The centered NC-0610 extension swaps or omits a weight separately in each of
the four phases. Each variant changes one encoded opening-row value through
ProverHook after an accepted complete baseline. All 32 field/repetition/phase
variants reach Pcs(ValueMismatch), before an affected-group query, with exact
transcript and local-hash prefixes.

The centered NC-0306/0307/0611 extensions cover both original sources, fields
and repetition counts with a zero opposite signed factor. One changed outer
coordinate rebuilds the retained row and dependent proof; the actual A3 join
point stays fixed. One changed retained row reaches ColumnMismatch on the first
authentic-path attempt. One changed final, including non-Boolean layer/inner
restoration, reaches ValueMismatch without an affected-source query. Accepted
complete native baselines and exact failure prefixes are required for all 32
variants; W failures consume X first.

The centered NC-0606 extension substitutes one genuinely verified original
range handle, rebuilds dependent proof messages, and retains the old source's
responses. Both sources, fields and repetition counts reach RootMismatch on
the first affected path, with exact transcript and local-hash prefixes.
The NC-0312 variant changes one opening-row value derived from a wrong output-group plane
and reaches ValueMismatch before queries. NC-0314 changes one reserved-plane
A3 final; exactly its physical zero equation fails, reaching
FinalEvaluationMismatch. These 16 variants require accepted complete native
baselines and add no catalog IDs or complete resource evidence.
