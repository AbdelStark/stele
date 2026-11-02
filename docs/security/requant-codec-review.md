# Native Requant expected descriptor and codec review

E7-01d3 implements the expected frames and complete untrusted proof preflight
in RFC-0023 §§1,2.3,2.4,4. Parent E7-01d retains actual registration and proof
consumers, native controls, complete wire/record/Usage/continuation parity and
resource-ledger requirements.

Root executed nine local checks on implementation commit
`66fd8241124d4cdcb9460b1a1b2227aa046c29fc`, checking source hashes before
and after. Receipt SHA256:
`7b50fefc9b33d65c6774d46106f874a2578e3515f8c1184c69b2954551618975`.
All nine Requant tests, eleven Python checks and both lifetime examples passed,
with formatting, strict targeted Clippy, Rust policy, RFC status, documentation
links and glossary checks. Both lifetime examples produced the intended E0515
diagnostic for the input or advice owner. The exact PR head must also pass the
full hosted workspace/native gates.

1. Public items: `Statement`, `Descriptor`, the existing `Limits` alias and
   `Schema::advice_source` implement RFC-0023 §§1,2.3,2.4,4. Expected geometry
   and frames use the immutable generated Schema and genuine borrowed input
   and advice certificates. The Source helper grants no authentication.
2. Challenges: none added or drawn. Preflight never replays a transcript.
   The expected eight-section partition follows the specified protocol order.
3. Claims: none emitted or accepted. The output uses the actual A1 Instance
   with eq, sign and ascending q planes; each byte retains its positive term
   followed by the negative twice-sign term. Actual consumers remain required.
4. Bindings: this slice checks expected metadata and untrusted shape. Genuine
   wrong source IDs, shapes and rates reject in both fields. Independent wire
   cases exercise outer/A5/A9 headers, canonical rows and arithmetic, child
   error causes, truncation and trailing bytes. These tests grant no native
   proof-control completion; NC-0308..0314 remain pending.
5. Soundness: no loss or ledger line changes. Public-payload and local-hash
   values are cumulative maxima, not observed Usage. The hash maximum includes
   one advice identity hash, both actual A5 maxima and three outer openings;
   standalone imports remain separate. The native union checks existing accounting.
6. Bounds: the existing generated CQIS record fixes row counts and equations.
   Checked arithmetic derives all geometry and IDs. No supplied polynomial,
   record bytes or proof field can replace the expected Schema or handles.
7. Padding: both actual range_8 A5 descriptors use all-one selectors over the
   complete physical sources. Full constraints retain sigma masks and all
   padding/reserved-row equations; the accepting parent must execute them.
8. Determinism: fixed byte, term, source and section order, including zero
   coefficients and repeated factors. There is no sampled or map-based ordering.
9. Parity: eight independent fixtures cover both fields and repetition counts,
   n=1/2/3, both target widths and unequal source rates. Every expected frame
   byte is compared; the explicit 274-byte caller context/identity region uses
   real imported handles. Independent outer proof/public/H totals are checked
   alongside actual unchanged A5 totals. Per field, 364 independent mutations
   yield 312 rejects and 52 intended opaque-response passes, including 12
   supported-field-tag swaps. These canonical-shape packets authenticate nothing.
10. Cost: O((4+R)N+E+J) expected metadata preparation in T_misc. The owner stores
    selectors and constructs temporary borrowed A5 descriptors without
    self-reference. Early position/public/proof lower bounds precede selector
    allocation; exact cumulative caps follow child sizing. Allocations are
    fallible. No measured constant or weight pass changes; complete observed
    memory and resource accounting remain parent obligations.
11. Verifier: the crate remains no_std. Complete lengths come from expected
    metadata, arithmetic is checked and preflight borrows slices. A9 response
    columns remain opaque until authentication. Advice root and packet-identity
    checks remain required before RequantStatement; each child's multiplicity
    checks stay at that child's entry. No accepting record is exposed.
12. Vocabulary: existing descriptor, source, plane, claim and constraint names
    follow the Accepted RFC. Exact API/evidence guards preserve existing corpora
    and add receipts to the existing commands; CI routes and dependencies are unchanged.

Root validation statement: I tried to break it by changing genuine source IDs,
using the other supported field tag, inserting noncanonical row/scalar limbs
and lowering each cumulative cap, and the controls
`rejects_codec_statement_and_sources`, `matches_reference_qm31_codec` and
`matches_reference_om31_codec` rejected the corresponding changes.
Opaque response-column changes intentionally pass this unauthenticated preflight.

Soundness/PCS-owner and GKR/RFC-owner reviewers verified the frozen source
and execution logs and approved this scope, subject to final hosted validation.
Their full twelve-item review SHA256 values are respectively
`30db83afeb506c4952dde0aedf75a220672c28248a8f230dc7d7941153c58587`
and `9a37caeec4278d475240b804a7dcaee7a4ed9af1b6e045954209132df8fa2947`.
