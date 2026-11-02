# Negative-control catalogue (INV-4). Every row is a test that must be *rejected* with the stated error.

| NC-id | Binding | RFC § | Tamper | Expected error | Status |
|---|---|---|---|---|---|
| NC-0001 | output token ↔ logits | 0004 §7 | flip one generated token | `DecodeMismatch` | todo |
| NC-0002 | residual cut ↔ layer | 0007 §3 | +1 on one `R_ℓ` element after capture | `ClaimMismatch(R_stack)` | todo |
| NC-0003 | weight block ↔ layer index | 0007 §2 | swap `W_Q` blocks of two layers | `FusedOpeningMismatch` | todo |
| NC-0004 | passport binding | 0011 | prove with another passport | `PassportRootMismatch` | todo |
| NC-0005 | prompt binding | 0001 §3 | change one prompt id in `io_digest` | `EmbeddingClaimMismatch` | todo |
| NC-0100–0109 | CQIS gadgets | 0004 §10 | see RFC | typed per gadget | todo |
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
| NC-0306 | matmul phases | 0007 A2 | one partial row uses a changed outer coordinate, fixed expected source and zero opposite factor | `ColumnMismatch` | done |
| NC-0307 | matmul phases | 0007 A2 | change one original final under a zero opposite factor; keep its opening row | `ValueMismatch` | done |
| NC-0308 | Requant input bytes | 0023 §6 | field-congruent int32 substituted in advice/arithmetic | `ValueMismatch` | done |
| NC-0309 | Requant advice identity | 0023 §6 | separately verified advice handle under unchanged packet | `CertificateContext` | done |
| NC-0310 | Requant full-width result | 0023 §6 | t=65537 and q=1 retain valid low division columns | `FinalEvaluationMismatch` | done |
| NC-0311 | Requant carry | 0023 §6 | one interior carry exceeds its cap or changes a column | `FinalEvaluationMismatch` | done |
| NC-0312 | Requant plane mapping | 0023 §6 | one producer group row uses the wrong plane | `ValueMismatch` | done |
| NC-0313 | Requant sign and target | 0023 §6 | s=1 at v=0 | `FinalEvaluationMismatch` | done |
| NC-0314 | Requant padding | 0023 §6 | one padded or reserved-plane byte becomes one | `RoundSumMismatch / FinalEvaluationMismatch` | done |
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
| NC-0500–0506 | attention | 0009 §7 | see RFC | | todo |
| NC-0600 | PCS | 0010 A9 | change one certificate codeword limb or opening row value under zero b; rebuild dependent responses | `ColumnMismatch` | done |
| NC-0601 | PCS | 0010 A9 | replace one derived query index and its response/path, retaining all other draws | `RootMismatch` | done |
| NC-0602 | PCS | 0010 §10, 0012 A3 | wrong leaf payload or sibling for fixed root/index, both tree kinds | `RootMismatch` | done |
| NC-0603–0605 | PCS | 0010 §10 | see RFC | | todo |
| NC-0606 | PCS | 0010 A9, 0007 A2, 0023 §6 | replace the expected certificate root or use a separately verified certificate for one unchanged opening; substitute one genuine Requant advice handle under its unchanged packet | `RootMismatch / CertificateContext` | done |
| NC-0607 | PCS | 0010 A9 | authenticate a leaf containing the M31 modulus at the certificate and opening consumers, including zero a | `NoncanonicalField` | done |
| NC-0608 | PCS | 0010 A9 | after valid verification, import certificate bytes with one changed leaf; cached context cannot replace re-verification | `RootMismatch` | done |
| NC-0609 | PCS | 0010 A9 | change an unused RFC-0006 A1 final; regenerate preceding openings so rejection reaches its terminal source | `ValueMismatch` | done |
| NC-0610 | PCS | 0010 A9 §4, 0008 A5 §7, 0023 §6 | change the expected scalar under zero b or one closed lookup mu-opening row value; replace one Requant source row using a swapped or omitted independent weight in each of four phases; reject before column draws | `ValueMismatch` | done |
| NC-0611 | PCS | 0010 A10, 0007 A2 | one retained opening-row value changed, with dependent final/responses reconstructed under a zero opposite factor | `ColumnMismatch` | done |
| NC-0700–0703 | passport | 0011 §6 | see RFC | | todo |
| NC-0800 | transcript/ledger | 0006 A1,A3, 0012 A1,A5 | one final evaluation folded at a challenge drawn before its round message | `FinalEvaluationMismatch` | done |
| NC-0801 | transcript/ledger | 0012 A1 | configuration: replace one registered label with another | `DuplicateLabel` | done |
| NC-0802 | transcript/ledger | 0006 A1,A2,A3,A4, 0008 A3,A5, 0010 A9, 0012 A1,A4,A5,A6,A9,A10,A11,A12,A13, 0007 A2 | next instance's one final value generated after omitting Final (including tree/selected-product), BatchFinal, ZeroFinal, OpeningColumns, Stack, StackSources, LookupStatement, LookupMultiplicities, LookupMultiplicityClaims, MatmulStatement either original matmul OpeningColumns, RequantStatement, RequantConstraints, each of three RequantClaims frames or final Requant OpeningColumns | `FinalEvaluationMismatch` | done |
| NC-0803 | transcript/ledger | 0010 A9, 0012 A10 | replace one query with a differing index drawn before CertificateRow or OpeningRow absorption | `RootMismatch` | done |
| NC-0804–0805 | transcript/ledger | 0012 §6 | see RFC | | todo |
| NC-0900–0901 | ZK | 0013 §6 | see RFC | | todo |
| NC-1000–1002 | GPU | 0014 §7 | see RFC | | todo |
| NC-1100–1101 | distributed | 0015 §7 | see RFC | | todo |
| NC-1200–1203 | verifier/wrapper | 0016 §7 | see RFC | | todo |
Coverage report: `scripts/gates/negative-controls.sh --coverage` lists claim-graph edges, PCS checks and ledger lines without a control.

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
