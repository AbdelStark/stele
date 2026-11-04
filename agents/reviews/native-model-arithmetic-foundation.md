# Native model-arithmetic foundation — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 static
§§1–6, flow §§1–3 and RMSNorm §§1–3. This checkpoint implements schemas
1–6 and 14. The remaining twelve schemas, complete Bounds collection, source
conversion, assigned controls and full task qualification remain required.

The public record has private bytes. Each constructor derives a closed schema
from separately supplied parameters, checking their domains before arithmetic.
LayerNorm/RMSNorm take the existing immutable checked descriptors. No supplied
record selects its own parameters, prime, radix, roles or counts. Validation
compares the complete generated frame, including its exact length. These APIs
provide static metadata; they authenticate no source and enforce no proof relation.

The private word holds exactly 2304 bits. Addition checks its final carry,
subtraction checks its final borrow, multiplication retains the full 4608-bit
product before rejecting nonzero high limbs, and shifts check capacity first.
Capped division binary-searches the exact integer quotient against complete
products; an overflowing positive product exceeds every representable numerator.
Zero divisor rejects. No field residue or narrowed machine integer selects a bound.

The private column builder retains both operand widths even when their product
is zero. It computes all term products and their exact sum before deriving caps,
uses the schema's radix, retains both zero boundary carries and checks each side
strictly below p/2. Its 269-column and 128-KiB limits are independent of supplied
bytes. Reservations are fallible; a failed construction returns no public record.
The fixed count cap is four terms, needed by the later decoding/request schemas.
Only private closed derivations can supply terms.

Affine bias and both embedding sources align before the common rounding roles.
Gated policies retain the full 8454661 scale domain. LayerNorm computes maxima
over all 33 joint exponent branches and keeps qmax=32768 for the variable original
denominator; it does not divide Ucap by Doutmax to narrow that bound. The new
RMSNorm schema includes the full original statistic, sign, lookup and output
chain while leaving RFC-0022's existing record bytes unchanged.

The fixture generator calls qualified pure integer derivations, without running
historical campaign mains. It supplies 1,565 configurations and 29 complete byte
records, including extreme exponent gaps, maximum dimensions/scales, d=1 and
normalization endpoints. Native tests compare exact bytes or full-frame hashes,
reject changed bytes, lengths, parameter domains and other valid parameter
authority, and preserve existing RFC-0022 fixtures. The private u2304 tests use
independent 32-bit-limb arithmetic, all 2,304 single-bit positions, and explicit
overflow/underflow/division and source-width boundaries.

## Workflow 03

1. Public parameters and constructors implement the cited closed schemas.
   The complete Model/Scales/Registry association is not yet provided here.
2. No challenge, transcript or absorb order changes.
3. No field claim is emitted. Actual source/range/rounding consumers remain
   separate required reductions.
4. Rejection tests cover this static construction boundary. No assigned NC id,
   including NC-0109, is marked complete by this checkpoint.
5. No soundness-ledger line changes; no new challenge or query is introduced.
6. The seven new instances derive only from static configuration. Original
   source joins, variable branch factors and narrower semantic ranges remain
   mandatory at their actual consumers.
7. These records retain schema-prescribed padding/index bounds. They neither
   admit padded lookups nor implement a proof mask or selector.
8. Fixed arrays, ordered roles and exact integer arithmetic determine all bytes.
9. Native/reference metadata parity passes on the stated configurations.
   No GPU change or proof-byte parity is claimed.
10. Static derivation belongs to T_misc. No weight pass or measured cost-model
    constant changes; no benchmark result is claimed.
11. The crate remains `no_std` with checked arithmetic and bounded fallible
    allocation. Public failures expose no partial record.
12. Existing Model, Scales, Registry, Bounds and operation vocabulary is retained.

I tried to break it by substituting parameters and frame bytes, overflowing wide
arithmetic, dropping high zero columns and exceeding the field bound, and the
control tests rejected those changes at their stated boundaries. This same-author
review does not approve the unfinished E5-03 task PR.
