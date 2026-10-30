# Full-row range capacity review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Evidence](../../research/cqis-bounds/RANGE-CAPACITY.md).

- Public items: Draft RFC-0004 A3 research capacity, for RFC-0021 §2.3's
  existing16384-element norm domain. No Accepted arithmetic rule changes.
- Challenges: no label, absorb order, challenge source or retry changes.
  Expected count/caps derive dimensions before payload access. Old-domain
  statement bytes remain unchanged; complete range/signed/xy consumers remain.
- Claims: all original/public MLE claims and complete fraction-tree consumers
  remain in their existing functions. Larger shape proofs exercise the same
  verifier at the existing maximum lookup dimension18.
- Bindings: the tests-first larger shape rejected at the old Capacity guard.
  All18 new geometry/witness cases passed. Oversized counts, padded byte-cell
  overflow and invalid norm dimensions reject before supplied payload use.
  All legacy controls passed. The maximum wide-range proof and padded-source
  control passed; the maximum signed32 and xy proofs remain pending.
- Ledger: exact formulas remain9a+7b and4a+3b per range; new maxima151 and67.
  Signed32 maximum663; xy maximum1606 and674 draws per label. Lookup losses
  remain separate, with m<=18 and2BN<=262144<p. Maximum wide-range runtime
  accounts passed at m=18, A3 numerator151 and67 draws per nonlookup label.
- Bounds: count<=65536 and padded N*B<=131072 are both required. Dropping
  either guard would admit a different resource domain. Byte-column side511
  and xy side65535 remain unchanged, each strictly below p/2.
- Padding: counts just above half-capacity round up to the full padded shape.
  Whole rows, high byte planes and carry endpoints stay in the actual proofs;
  zero caps remain explicit. No selector removes a required boundary.
- Determinism: fixed tuple/row/plane order, exact integer bounds and identical
  encodings on the old domain. The20 wide,24 signed and16 xy proofs retain
  their frozen digests. Required local repository gates passed.
- Parity: native CPU/SIMD/CUDA unchanged. The full large-range reference proof
  passed; signed32 and normxy remain pending. No native/private inference claim.
- Costs: maximum word-byte/lookup work unchanged; more narrow words increase
  cap metadata from at most81920 to1310720 bytes and terminal A3 entries
  from4096 to65536. Charge these changes in T_misc/c_sc.
  No measured constant, benchmark or additional weight pass.
- Verifier: native no_std unchanged. Count is checked before iterating caps;
  the padded cell bound is checked before reading witness/proof data. Namespace,
  field validation and actual proof consumers are unchanged.
- Glossary/history: append-only Draft/accounting entry. Existing adapter caps
  outside xy remain. Original task criteria, physical ownership and privacy
  requirements are unchanged.

I tried to break it by adding one160-bit row beyond the padded byte-cell limit,
and the control Capacity rejected it before inspecting the missing payload.
