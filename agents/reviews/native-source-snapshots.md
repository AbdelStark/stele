# Native original-file snapshots — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 source §4.
SourceSnapshot validates a complete original File and rechecks later chunk reads.
This supplies file integrity for the pending package loader. It does not validate
a safetensors container, index, selection, raw alias, SourceConfig or conversion.

The initial pass checks declared length, exact EOF and whole-file SHA-256.
Both the complete-file hash and each private chunk digest consume the same
buffer contents. No snapshot escapes a failed pass. The index retains exactly
32 digest bytes per 65536-byte chunk, with a possibly shorter final chunk.
Count, index bytes and the caller's explicit budget are checked before reading
or allocating. Vectors reserve fallibly; temporary byte storage is at most
65536 bytes. Allocation bookkeeping and the snapshot object are additional.

Every replay derives its absolute offset and length from that checked index
and original file extent. Reads may be short but cannot overreport, truncate,
reorder or replace the checked bytes. The entire chunk hash is compared before
returning an owned immutable SourceChunk. Appended bytes outside the original
extent are never consumed; the initial snapshot still requires exact EOF.
Caller-retained chunks consume additional memory under the caller's ownership.
There is no constructor from supplied digests or unchecked partial file bytes.

The private chunk index is neither serialized nor committed. Canonical Source
and Assets identities remain unchanged. Its additional SHA-256 invocations are
listed in the deterministic hash-use inventory, including replay mismatches and
repeated work. No profile budget, Q12 theorem or source authority is inferred.
ADR-052 records the pinned SHA dependency and bounded replay design. The crate
uses the documented incremental and fixed-output [RustCrypto API](https://docs.rs/sha2/0.11.1/sha2/),
with default features disabled and locked transitive checksums.

Independent Python hashlib fixtures cover 52 complete byte streams: SHA padding
boundaries, zero length, chunk boundaries, random lengths and a 5242881-byte
stream. These are byte fixtures, not model tensors. Tests compare replayed bytes in
reverse chunk order, short reads, exact budgets and out-of-range requests.
Single-byte changes at both sides of a chunk boundary and the final byte reject
in both initial hashing and replay. Other controls cover replacement, reordering,
truncation, suffixes, callback failures, overreported reads and immutable returned
bytes after backing-buffer changes. A u64-maximum declared length with an
insufficient budget rejects before any callback. That is metadata admission,
not evidence of reading a maximum-length or original named-model file.

## Workflow 03

1. SourceSnapshot and SourceChunk implement native snapshot integrity in source §4.
2. No Fiat-Shamir challenge or transcript order changes.
3. Only verified file bytes escape. Full package, numerical and passport consumers
   remain required; no proof claim is emitted.
4. The native source_snapshots test rejects one-byte initial/replay changes with
   FileDigest/SnapshotData. No assigned production NC id is marked complete.
5. The deterministic inventory adds actual local chunk SHA-256 uses. No algebraic
   ledger formula changes; the existing accounting gate remains required.
6. No arithmetic bound certificate changes or runtime maxima are introduced.
7. Full initial file bytes, including headers and padding, are hashed. Container
   coverage and selected/ignored tensor semantics remain package obligations.
8. Fixed chunk boundaries and exact bytes determine validation; callback order
   cannot change accepted byte contents or canonical Source identities.
9. Native whole-file hashes match Python hashlib for every stated fixture.
   Original-model, CPU/GPU proof and inference parity are not claimed.
10. Hashing and validation remain preparation T_misc. No online weight pass,
    benchmark constant or speedup claim changes.
11. Source code remains no_std and forbids unsafe code. Lengths and offsets are
    checked; explicit index admission and fallible bounded buffers govern memory.
12. File, Source, snapshot, chunk and original-byte terminology retain source §4's
    distinction between declarations, verified bytes and consuming authority.

I tried to break it by replacing one original byte between reads, and the control
rejected it with SnapshotData before any changed chunk escaped. This same-author
review does not approve the unfinished E5-03 task PR.
