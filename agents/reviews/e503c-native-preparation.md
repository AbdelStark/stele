# Complete native numerical preparation — E5-03c

E5-03c implements and qualifies native numerical preparation from complete
original GPT-2-small and Llama-3.1-8B sources, for int8 and int4 matrices.
This is the complete prerequisite accepted in RFC-0025 A1 and ADR-056.
Original E5-03 remains incomplete, with every original acceptance line retained.

## Original-source evidence

Every selected original scalar and every Artifact, Scales, SourceConfig,
Registry, Bounds and numerical identity byte agrees with the independent
checker. Native preparation also rereads each complete stored Artifact under
its emitted digest. These are exact extents, not benchmark results.

| Qualification receipt | Selected scalars | Physical records | Static records | Artifact bytes |
|---|---:|---:|---:|---:|
| [gpt2-int8](e503c-original-preparation/gpt2-int8.json) | 124439808 | 196 | 478 | 124840091 |
| [gpt2-int4](e503c-original-preparation/gpt2-int4.json) | 124439808 | 196 | 478 | 62680859 |
| [llama-int8](e503c-original-preparation/llama-int8.json) | 8030261248 | 291 | 1164 | 8033809270 |
| [llama-int4](e503c-original-preparation/llama-int4.json) | 8030261248 | 291 | 1164 | 4018811766 |

The [manifest](e503c-original-preparation/manifest.json) pins each unchanged
receipt, executable and complete committed source. The receipts contain every
original file SHA-256, all native/checker source pins and all eleven output hashes.
The committed-source mapping distinguishes a receipt's launch head from the
later checkpoint commit containing its exact pinned files. Every mapped file
was checked against Git; all output hashes were rechecked before packaging.
The [65 qualified reference source pins](e503c-original-preparation/reference-sources.json)
remain unchanged.

GPT-2 uses original revision 607a30d783dfa663caf39e06633721c8d4cfcd7e.
Llama uses original revision d04e592bb4f6aa9cfee91e2e20afa771667e1d4b;
the [complete acquisition receipt](e503c-original-preparation/llama-acquisition.json)
records all four BF16 shards and nine supporting files, with complete SHA-256
and upstream LFS or Git blob identities. No checkpoint weights are included here.
Every original dimension and physical role remains, including GPT-2's tied head
and Llama's separate original head. ADR-054/055/057 state the fixed numerical
inputs; they are qualification choices, not calibrated defaults or fidelity claims.

The Llama checker decodes all 65280 finite BF16 encodings independently, checks
10000 exact rounding cases and legal nibble packing, then compares all original
scalars in bounded row chunks using integer fields and Fraction inequalities.
Complete row maxima determine the least matrix exponent and each least positive
mantissa. No floating-point arithmetic, clipping, sampled payload or smaller
model supplies original-model credit.

The [frozen RoPE evidence](../../crates/stele-cqis/tests/fixtures/original-llama-rotation-reference/README.md)
supplies only the independent digest for the identical full rotation definition.
Its exact receipt, full output files and unchanged research sources are checked
before extraction. Both native runs regenerate all 8388608 coefficient pairs;
all other independent function data is regenerated. The historical Model and
Registry are never substituted for either original-source Model or Registry.

## Acceptance and review

Same author acting in the required cqis-numerics and soundness-auditor roles;
this is not an independent-review claim.

| E5-03c requirement | Implementation and evidence |
|---|---|
| Full native construction and original int8/int4 parity | Four complete receipts above; [GPT-2 adapter review](native-original-gpt2-preparation.md), [SourceConfig](native-source-architecture.md), [conversion](native-source-conversion.md), [Registry](native-registry-validation.md) and [complete Bounds](native-model-bound-collection.md). |
| All nineteen schemas, formats, transforms and row cases | [Arithmetic schemas](native-model-arithmetic-schemas.md), [row conversion](native-row-conversion.md), [source formats and transforms](native-source-conversion.md); complete randomized/boundary fixtures and the required workspace gate pass. |
| Immutable ownership joins and numerical tamper rejection | [Preparation composition and identity](native-numerical-identity.md), [source package](native-source-package.md), [snapshots](native-source-snapshots.md), [Artifact validation](native-artifact-streams.md); original outputs are preserved read-only with pinned receipts. |
| No production-control substitution | Control catalogue unchanged. NC-0109 and all original E5-03 requirements remain due at their actual consumers under [A1 sequencing](e503-sequencing-acceptance.md). |

1. Public numerical APIs implement RFC-0025 sections 2–6 and its source,
   conversion, encoding and collection appendices. The linked component reviews
   map constructors, validators and accessors to those contracts. RFC-0022's
   existing function APIs and canonical bytes remain regression checked.
2. No Fiat–Shamir challenge, transcript label, absorb order or random reduction
   is introduced.
3. No proof claim is emitted. Numerical objects cannot supply expected publisher,
   registrant, commitment, inference, Passport or profile authority.
4. Native numerical controls change original bytes, source configuration with
   fresh file hashes, stored output, scales and child identities under fixed
   expectations. Their rejection reasons are checked. They do not complete
   NC-0118..0122, NC-0704..0710 or any other production catalogue reservation.
5. The soundness inventory adds the private snapshot SHA-256 calls: every initial
   full File and chunk, and every full replayed chunk including failed/repeated
   work. The combined accounting gate passes. No new loss theorem, challenge
   budget, Q12/Q29 resolution or profile admission follows.
6. All nineteen schema instances and complete collections derive statically from
   checked configuration, scales and full geometry. Runtime maxima and short
   requests cannot relax arithmetic certificates.
7. Artifact framing checks every code and padding byte, with continuous int4
   packing across rows and only the final permitted padding nibble. Ignored
   original buffers cannot choose runtime masks or selectors.
8. Fixed physical order, exact integer rounding, minimal scales and canonical
   frames determine outputs. No hash-map iteration, timing input or host float
   enters native preparation.
9. Full native/independent numerical byte parity passes for both original models
   and both precisions. CPU/GPU proof parity remains a downstream obligation;
   no GPU code changes here.
10. This is offline preparation T_misc. The prescribed source scans do not add
    an online weight pass. No fitted cost constant or performance result changes,
    so no benchmark ledger entry is asserted.
11. Core remains no_std and forbids unsafe code. Checked shape-derived lengths,
    fallible bounded allocation, exact EOF and I/O error propagation retain the
    component-reviewed limits. The separate filesystem adapter uses std and
    exclusive output creation; failure never yields a completed result.
12. Source, Assets, SourceConfig, Preparation, Artifact, Model, Scales, Registry,
    Bounds and numerical identity retain their canonical meanings. A successful
    numerical receipt is not a proof or Passport.

I tried to break it by changing a final selected scalar to nonfinite, changing
source bytes after emission began, changing a stored vector byte, and supplying
a changed source epsilon with fresh file hashes; the native controls rejected
them with SourceNonfinite, SnapshotData, Identity and SourceEpsilon respectively.

The required local suite passes: formatting, all-target/all-feature Clippy,
workspace and example tests, no-default-features, the combined digest/control/
accounting gate, CI tooling, Rust policy, ledger validation, RFC references,
documentation links, glossary and the bounded model-contract checks. Dependency
bans pass separately. The gate receipt SHA-256 is
257f68e2498b2c8f1f4e021288c0ace9af548dbb3b2b084895433b56c175730c.
The selected hosted native, native-union, native/model research and all 28 table
partitions must still pass on the PR before merge. No partial original-task PR
or production-control completion is authorized by these numerical results.

Reproduction uses the `prepare_source` example built with `--profile test`, the
manual `qualify_original_gpt2.py` or `qualify_original_llama.py` checker under
its pinned dependency versions, complete authorized original files, an explicit
native executable, `--weight-bits 8` or `4`, and a fresh output directory. Llama
also requires `--rotation-reference` pointing to the bundled reference directory
linked above. The checkers validate full source and output bytes; they do not
consume the saved success receipts as a validation bypass. Full original runs
remain manual qualification and are not added to routine CI.
