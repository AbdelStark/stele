# Complete original GPT-2 preparation — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of the manual native
disk adapter and complete original-source qualification. The source is
[GPT-2-small at the pinned revision](https://huggingface.co/openai-community/gpt2/tree/607a30d783dfa663caf39e06633721c8d4cfcd7e).
The whole 548105171-byte checkpoint matches upstream LFS SHA-256
`248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707`.
The config, tokenizer, vocabulary, merges, tokenizer config and generation config
also match that revision's complete original files. No remote model code runs.

ADR-054 records the explicit numerical choices. The source architecture keeps
every original dimension and epsilon; all 124439808 selected scalars and 196
physical records are consumed. The 12 legacy mask buffers receive complete
source hashing and structural coverage. They cannot select CQIS masks. No second
GPT-2 head tensor is introduced.

The native adapter consumes independently supplied Model, Preparation, Source,
Assets and an explicit layout. It hashes/checks the complete original package,
checks SourceConfig, derives minimal source scales and streams Artifact to a new
file. It flushes and rereads the actual file under the emitted digest, then fully
regenerates Registry and emits every static Bounds record and the numerical
identity. Output creation is exclusive. The final result is written only after
all these steps; a partial directory after an error is not a completed run.

Metadata input lengths are bounded before fallible allocation and exact EOF is
checked. Source reads use already opened files and full u64 seek offsets, then
the existing snapshot checks. Adapter allowances are 4096 open file descriptions,
32 MiB for snapshot indexes, 64 MiB for metadata and 64 MiB for the source cache;
the converter's actual required cache is admitted before conversion. These are
separate host limits. They change no canonical field, shape or source domain.

The independent checker memory-maps original raw bytes and reads bounded row
chunks. Every scalar is decoded from integer IEEE fields. Finite positive F32
magnitudes order exactly by unsigned absolute encoding, so complete row maxima
can be selected without float casts. Fraction arithmetic independently chooses
the least matrix exponent and every minimal row mantissa. Code rounding uses
integer quotient/remainder with exact half-away ties. Negative shifts at least
25 must round to zero because the significand is below 2^24; nonzero positive
shifts at least 40 necessarily overflow either code range even at mantissa 65535.
All remaining numerator/denominator operations fit u64. A separate 10000-case
Fraction check exercises that vectorized rounding implementation.

Every Artifact byte is compared in order, including metadata, scales, codes,
record sizes and EOF. All 478 static Bounds records are independently derived
and compared in full, as are complete Registry bytes, SourceConfig and cqis_id.
The qualified reference helpers remain unchanged; no historical campaign runs.
The native digest_cqis is
`0381c94a2ed6f017a4d8d95edb416ed8853bcbe84b1c01e376f63ac3ba688e09`,
and cqis_id is
`4c6ae6e4b8d5596b0223ea76298b5ffd15eb0020e5910d9ac88f6e0f24cadd82`.

Reproduction uses the `prepare_source` example built with `--profile test`, then
`tests/support/qualify_original_gpt2.py` under the dependency versions in its
docstring, with `--source-dir`, `--native` and a new `--output-dir`. Paths are
relative to `crates/stele-cqis` for the script, and the native executable path is
explicit. The script pins original SHA-256 values, native/source code identities
and all output file hashes. Keep the generated receipt with those artifacts.

## Workflow 03

1. The example composes RFC-0025 source, conversion, source architecture, encoding
   §6 and collection contracts. It adds no public core API or protocol schema.
2. No challenges, transcript labels or absorb orders change.
3. No proof claim is emitted. Numerical preparation does not supply publisher,
   registrant, commitment, inference, fidelity or proof authority.
4. The existing native numerical controls retain their scope. Disk checks also
   reject a changed source suffix before output and refuse an existing output
   directory without changing its files. Production catalogue IDs stay pending.
5. No new random loss or security-budget term. All original hash/source and actual
   proof-consumer obligations remain; self-selected hashes confer no authority.
6. The complete Bounds collection is static and uses full model geometry and
   declared ranges. Runtime values and short sequences cannot relax it.
7. Full Artifact validation retains every code/padding check. Legacy source
   buffers never supply runtime selectors or masks.
8. The source revision, every numerical choice, scalar order and output frame are
   fixed. No floating-point arithmetic or calibration is used.
9. Original GPT-2 preparation has complete byte parity. Llama, full inference,
   fidelity and CPU/GPU proof parity remain required.
10. Offline preparation affects T_misc only. Byte/record counts are exact extents,
    not measured throughput results. No online weight pass or fitted term changes.
11. Core remains no_std and unchanged. This filesystem example uses std, forbids
    unsafe, checks metadata caps and propagates I/O/numerical failure.
12. Original Source, Assets, Preparation, Scales, Artifact, Bounds and cqis_id
    retain their meanings. The final JSON is a qualification result, not a passport.

I tried to break it by appending a byte to an original source file and reusing an
existing output directory; the adapter rejected both and preserved the completed
output. This same-author review does not approve the unfinished E5-03 task PR.

Validation: complete original GPT-2 qualification passes. A separate disk run of
the indexed Llama fixture matches all five expected output frames and Bounds
identity; it supplies adapter I/O coverage, not original Llama qualification.
The example build, Clippy, formatting, 530 Accepted RFC references, Rust policy
and 755 local documentation links pass. ADR history remains append-only and all
65 qualified reference/helper files remain unchanged. Full checkpoint conversion
is an explicit manual qualification, with receipts; it is not added to routine CI.

## Complete int4 qualification

ADR-055 adds an explicit `--weight-bits 4` manual run. The default remains int8;
its Model and Preparation bytes match the frozen int8 inputs. Changing only
matrix precision leaves all source dimensions, vector fractions, source roles,
assets and other numerical parameters unchanged. The core converter is unchanged.

The independent checker derives Q from the selected precision, selects the least
exponent and each row mantissa with exact Fraction inequalities, and compares
every packed code. Int4 uses low nibble first across row boundaries; only the
last odd code receives a zero high nibble. Every nonfinal chunk has 128 rows,
so it contains an even number of codes even for an odd row width. Direct packing
checks cover all 225 legal nibble pairs, all 15 singletons and an odd-width
three-row tensor. The existing 10000 exact scalar rounding checks also pass.

The full original-source run passes for all 124439808 selected scalars, 196
physical records and 478 static records. Every Artifact, Scales, SourceConfig,
Registry, Bounds and identity byte agrees with the independent checker.
The int4 Artifact is 62680859 bytes; this is an exact extent, not a benchmark.
Its digest_cqis is
`ed3240bde1f76d911bb82a37bef43a184408ab3cab8871747ff46c97be6d06f2`,
and cqis_id is
`5508580624931d7ab8817fb360e829fc9b031fda5708150f36a1f01b4562c7f6`.
The qualification receipt SHA-256 is
`020ca496e657ffaf063220103ff82b52abc74532d65d748b95bb1a34d9642a56`;
its native executable SHA-256 is
`cec826032cb4cb7374c41caacfc03ccc0c38ad6640c66878c13185d0e56f40bc`.
The receipt records all 77 source pins and all 11 output file hashes. Outputs
and the exact executable are preserved read-only; the int8 run is unchanged.

The twelve review answers above still apply: this change extends a manual
checker without changing a native API, challenge, claim, certificate schema,
verifier or online cost. It supplies original GPT-2 int4 preparation parity,
not inference, fidelity or a production control. E5-03 remains incomplete;
see the [completion dependency audit](e503-completion-dependencies.md).

Validation for this extension: full native preparation, exact scalar/packing
checks, unchanged default inputs, formatting, Rust policy, 533 Accepted RFC
references, 757 local documentation targets and both existing task-graph tests
pass. The 65 qualified reference helpers remain unchanged. Accepted RFC text and
ADR history are preserved as prefixes; no production control is marked done.
