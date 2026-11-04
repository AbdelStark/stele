# Native exact source conversion — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 §2.1 and
conversion §§1–3. Conversion consumes a completed SourcePackage and the exact
Model/Preparation/Map combination. It derives minimal Scales, validates every
selected scalar/vector before output, and emits a complete canonical Artifact.
Original named-checkpoint qualification, SourceConfig/tokenizer/publisher
authority, inference/fidelity, production NCs and proof admission remain separate.

Scalar decoding uses integer sign/exponent/significand operations for all four
source formats. Subnormals retain their exact value, signed zeros normalize to
zero, and every selected NaN/infinity rejects. The normalized odd significand
has at most 53 bits. Magnitude comparisons first compare top-bit positions, then
align the exact significands at bit 63. No large host shift or float cast occurs.

The matrix exponent is the least e satisfying the complete-source maximum bound.
Each row receives the least positive u16 mantissa from its own maximum and that
same exponent. A zero row retains its matrix exponent and mantissa one; an all-zero
matrix has exponent zero. Fused Q/K/V parts derive independent scales. Exact
quotient/remainder arithmetic performs one half-away rounding. A denominator
strictly above twice the numerator implies a rounded zero but a ceiling of one.
A shifted numerator exceeding 64 bits cannot fit any allowed output after division
by a denominator of at most 16 bits, so it rejects without truncation. The other
quotient/remainder calculations and doubled remainders fit u64. Int16 vectors
retain their configured fractions and asymmetric endpoints; overflow never clips.

Source coordinates use the checked copy, transpose, fused-column or fused-bias
formulas, full u64 offsets and full source extents. A scalar may cross two original
snapshot chunks. Every fetched chunk is revalidated before its bytes are used.
Owned chunks may be reused without trusting a later external digest or mutable
buffer. The cache belongs to one immutable package and automatically clears on
every physical-ordinal change, preventing relative-offset reuse across sources.

Consecutive views need one cache slot. Transposed raw rows spanning at least one
chunk use a slot per input column; shorter raw rows use their complete contiguous
chunk span. This avoids the row-stride collisions of a fixed modulo cache. Each
slot owns at most 65536 original bytes, and the full requested slot/buffer allowance
is checked before source I/O. These are original raw bytes, never a whole matrix
of decoded scalars or an array of all row maxima. Scales retains its existing
64 MiB limit. Record vectors, bounded stream buffers, the already completed input
package, stack storage and allocator rounding/bookkeeping are separate. All new
heap reservations remain fallible.

The complete physical traversal validates all selected scalars and vector ranges
before any output callback. Matrices receive two complete logical scans for scale
derivation, then one for code emission; cache reuse does not skip numerical work.
The private Scales constructor checks every ordinal-derived row count, exponent
and positive mantissa, then hashes canonical bytes without a second whole frame.
The existing Artifact writer validates and hashes metadata and every emitted code.
Packing is continuous across odd rows; only an odd final high nibble is padding.

Short, overreported and failed writes return no Conversion. Source replay errors
during emission retain their original reason through the generic Artifact reader.
Earlier output is unusable after a failure. A successful callback acknowledgement
does not establish storage contents: actual stored Artifact bytes still require
validation against the emitted identity. No opaque supplied scales, payloads or
source hash can construct a successful numerical Conversion.

The 99 complete fixtures contain 70 accepted conversions and 29 rejections.
Sixty-nine accepted cases compare every Scale and Artifact byte against a full
independent Fraction oracle and the pinned research converter. The remaining
accepted case converts all 4194305 selected elements from an odd five-column
matrix, using complete analytically repeated expected bytes checked against an
independent exact row oracle. Its final-value nonfinite control must reject before
the first write. Sparse fixture readers emit the complete original bytes and
pass full original-file SHA-256 verification; no sampled payload is admitted.

The scalar test compares 10424 boundary/random cases, including over 10000 finite
vector-rounding inputs, and exhaustively enumerates
all 65536 bit patterns for each of binary16 and bfloat16 against independent
canonical decode digests. Fixtures also cover both transpose-cache layouts,
unaligned headers and cross-chunk scalars, zero rows, separate fused exponents,
ignored nonfinite buffers, signed-zero/source-identity distinctions, shard
repartitioning, and vector half/endpoints. Controls retain the expected original
Model/Map, reject insufficient cache allowance before I/O, reject original-byte
changes before and during emission, reject faulty sinks, and detect a changed
stored vector byte under the original Artifact digest.

## Workflow 03

1. Conversion::write_to and its result accessors implement conversion §§1–3 and
   RFC-0025 §2.1. required_cache_bytes describes native admission for source §4's
   authenticated chunks; it adds no canonical protocol field.
2. No challenge, transcript label or absorb-order changes occur.
3. No proof claim is emitted. Scales and Artifact are exact numerical outputs;
   actual stored-byte, expected source/passport and proof consumers remain due.
4. The native source_conversion controls exercise the bindings and failure reasons
   described above. Production NC-0118/0119/0120/0121/0122 and NC-0704..0710 retain
   their original owning-consumer requirements; these fixtures do not mark them done.
5. Existing inventory covers original snapshot replay, complete Scales and Artifact
   hashes. Cache reuse requires owned verified bytes; no query-loss formula or
   profile budget changes. Full task accounting/native gates remain due.
6. No bound-certificate schema or static limit changes. Conversion does not make
   runtime maxima into arithmetic proof bounds.
7. Continuous int4 packing and its one permitted final padding nibble are checked
   by the existing Artifact writer. Ignored buffers never choose runtime masks.
8. Physical order, exact coordinates, cache selection and rounding are deterministic.
   No hash-map order, floating point, inferred precision or calibration is used.
9. Complete native fixture bytes match independent results. Original full named
   checkpoints, inference, fidelity and CPU/GPU proof parity are not claimed.
10. This is offline preparation T_misc with the prescribed logical scans and no
    additional online weight pass. Resource controls bound raw reads for the
    transpose fixtures; no measured throughput constant or benchmark is claimed.
11. The crate remains no_std and forbids unsafe code. Lengths derive from checked
    Shape/Map/source extents; no former research element-count cap is restored.
12. Source, Preparation, Scales, Artifact, physical role and exponent/mantissa terms
    retain their specified meanings. Conversion identity is not proof admission.

I tried to break it by moving a nonfinite value to the last selected scalar,
changing source bytes only after emission began, and altering one stored vector
byte, and the controls rejected them with SourceNonfinite, SnapshotData and
Identity respectively. This same-author review does not approve the unfinished
E5-03 task PR.

Validation: the complete conversion and scalar fixtures, existing Scales and
Artifact stream regressions, all-target Clippy, no-default-features check,
30 documentation tests, formatting, RFC references, Rust policy and local
documentation-link gate pass. The qualified Python and legacy helper sources
remain unchanged; no historical campaign entry point was executed.
