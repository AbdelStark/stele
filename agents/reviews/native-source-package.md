# Native complete source package — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 source
§§1–4. SourcePackage joins original files, Source/Assets declarations and the
complete checked SourceMap before returning raw tensor or auxiliary views.
External authority, expected adapter completeness, SourceConfig semantics and
exact source conversion remain required before model or proof admission.

The constructor first checks joint u64 file length and the exact disjoint supplied
label set. It preflights all retained snapshot digest bytes. File snapshots then
check complete lengths, SHA-256 and EOF for every checkpoint, index, config,
tokenizer and generation file. No file label authorizes filesystem access.

Container and index parsing revalidate original chunks and share one conservative
metadata budget. Every globally duplicated tensor name rejects, including ignored
tensors. The index must name exactly the declared shard set and assign every
actual tensor to its exact file; even an unused empty declared shard rejects.
Its total_size must equal all validated payload spans. Selected, alias and ignored
names must equal the actual tensor-name union. Every physical entry then checks
its raw dtype, complete source shape and byte length. Fused source sharing remains
the exact partition already validated by SourceMap.

GPT-2's optional token/head alias must match raw dtype, shape and every original
byte. The comparison traverses both complete views through revalidated chunks;
different file offsets and chunk boundaries do not skip bytes. This check precedes
the completed package. Integer conversion and scalar finiteness remain required.

Only a completed package can issue SourceView. Physical ordinals select the
checked raw source extent; fused/transposed sources retain their full original
layout until conversion applies the exact Map transform. Auxiliary access is
restricted to declared Assets roles. Every consuming read revalidates a whole
snapshot chunk, then returns an owned SourceSlice restricted to the view's extent.
Offsets outside the view fail before I/O. No public unchecked constructor or
mutable metadata/payload accessor exists.

The snapshot budget covers the complete sum of chunk-digest bytes. One shared
metadata budget charges file/route vectors, all parser allocations and freed
temporaries before fallible allocation. That accounting is conservative, without
refunds. Allocator rounding/bookkeeping is separate. Construction uses at most
two bounded chunk buffers during alias comparison; returned slices consume their
own caller-controlled storage. Tensor payloads are not retained in the package.

The 39 independent fixtures include 25 complete valid packages and 14 semantic
rejections. Both small family role sets, single/indexed sources, generation presence,
fused/transpose mappings and original raw aliases are exercised. One valid fixture
has a complete 4800000-element source tensor and equal alias; another changes only
the alias's final byte under updated complete-file hashes and must reject. Sparse
fixture readers supply the full original bytes without embedding large payloads
in the Rust executable. These are synthetic source fixtures, not named-model
qualification, conversion, inference or fidelity evidence.

Native controls also cover exact file sets, joint-role collisions, aggregate
length overflow, missing/unlisted tensors, selected dtype/shape changes, wrong
shard assignment/total, cross-shard duplication, invalid containers, metadata
admission, short/error/truncated/extra reads and whole-file hash changes in every
file role. Every returned physical/asset view is read completely and hashed against
the independent original bytes. Replayed last-byte mutation is rejected.

## Workflow 03

1. SourcePackage implements source §§1–4; SourceView/SourceSlice implement §4's
   same-byte consuming requirement after the complete §2/§3 joins.
2. No challenge, transcript label or absorb order changes.
3. No proof claim is emitted. SourceConfig and exact conversion must consume these
   same bytes, with independently expected source/model/passport authority.
4. The source_package native test rejects the stated one-value semantic changes
   and updated-hash alias substitutions. Assigned production NC registration and
   the complete E5-03 task qualification remain required in the task PR.
5. All initial, parsing, alias and consuming reads use the existing complete-file
   and chunk SHA-256 inventory. No new loss formula or profile budget is claimed.
6. No arithmetic bound changes or runtime maxima enter static certificates.
7. Coverage includes every ignored tensor and original file byte. Actual selected
   scalar finiteness and numerical transformations remain conversion obligations.
8. Exact file labels and decoded tensor names determine deterministic sorted joins.
   Original source identities are retained; JSON is never reserialized for hashing.
9. Complete native raw views match the independent fixture bytes. Original named
   checkpoints, inference and CPU/GPU proof parity are not claimed.
10. Preparation remains T_misc; alias comparison adds no online weight pass and
    establishes no measured performance constant.
11. The crate remains no_std and forbids unsafe code. Offsets come from checked
    containers; budgets cover aggregate preparation metadata, not just each shard.
12. Source, Assets, index, shard, tensor, view and original-byte terms are retained.

I tried to break it by updating the source hashes after changing only the final
byte of a large raw alias, and the control rejected it with SourceAlias before
any package view escaped. This same-author review does not approve the unfinished
E5-03 task PR.
