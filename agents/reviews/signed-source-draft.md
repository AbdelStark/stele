# Signed source consumers — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. Scope: RFC-0004 A1 / Draft A3,
unchanged RFC-0006 A3 and range_8. [Evidence](../../research/cqis-bounds/SIGNED-SOURCE.md).

- Public items: exact expected signed-source schema, witness/producer and complete
  revealing verifier. Integer semantics implement the A1 canonical sign obligation;
  u32 byte-word roots and their composition are research, not native model sources.
- Challenges/absorbs: four raw/magnitude/sign/carry roots and three completed actual
  range states precede the ordered six A3 invocations. Every Final is absorbed,
  including zero dimensions. Existing labels only; no retry or new random inverse.
- Claims/consumers: all 16 new claims reach exact MLE evaluations of authenticated
  arrays or fixed slices/broadcasts. Incoming C0 is public0. Consumers use emitted
  points, including branches whose coefficients vanish. Nested ranges retain all
  nine A3 and 2r lookup claims each; no witness-generation claim is trusted.
- Bindings/controls: root/opening mutations, wrong sign/magnitude, positive INT_MIN,
  negative zero, fractional/nonbit/inactive carries, padding, coherent linear finals,
  inactive branches and actual range endpoints have exact-error controls. No native
  NC credit. H7=128 makes all signed equations hold for false positive INT_MIN,
  but the actual sign/high7 range rejects it. Magnitude cap+1 fails its range too.
- Ledger: new signed A3 loss is (16a+12b)/|K|; full range A3 adds (27a+14b+9)/|K|.
  Three lookup dimensions retain separate repeated identities and reductions.
  Exact records and draw counts are checked; FS/H, binding and joint ZK stay open.
- Static certificate: widths and dimensions come only from expected Spec. Raw,
  magnitude, sign and high7 caps are fixed; byte-column sides <=511 and 2*511<p.
  TopBit fixes S, Positive gives U=M<H, Negative telescopes U+M=2^bits. No full
  signed field embedding, runtime max, saturated result or unsupported chunking.
- Padding/masks: actual ranges force zero raw/magnitude/sign/high7 padding. The
  identities apply to all rows; carries there are zero. All byte planes are live
  for the selected format. This makes no inference about a model's masks.
- Determinism: fixed derivation, framing, ordering, field dimensions and transcripts.
  The 10000-case codec oracle and 24 complete states are frozen. Host bool rejection
  tightens shared research A3 parsing without changing any valid encoded message.
- Parity: both extension fields and repetitions, all widths and padded rows tested.
  Naive/folded A3 proofs agree, and existing batching/zerocheck vectors are checked
  after canonical field parsing is tightened. Native CPU/SIMD/GPU is unchanged.
- Costs: O(NB) new witness and producer work, inherited nonsuccinct reference
  verification. No measurement, new physical weight pass, production constant,
  committed intermediate or invented benchmark. Private composition stays open.
- Verifier: production no_std untouched. Capacity precedes payload access; exact
  object proof shapes and integer limbs are enforced. The pre-fix numeric-bool
  alias was reproduced as accepted, then rejected directly and inside range A3.
- Glossary/history: append-only Draft/accounting evidence; original E5-03 status
  and acceptance criteria remain. Actual signed operations and model ownership,
  native plan/codec and private proof composition remain required.

I tried to break it by assigning positive sign to INT_MIN with H7=128 while
preserving every signed equation, and the control Sign:TerminalCarry:RoundSumMismatch
rejected it through the actual range proof. Inactive-branch substitutions also
reject at their actual ClaimMismatch consumers.
