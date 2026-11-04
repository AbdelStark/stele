# Native original shard index — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025 source §2.
SourceIndex reads every original index byte through a completed SourceSnapshot.
It returns a complete closed mapping and declared total_size. The complete
package must still join actual shard membership, tensor names and payload total.

The index has a JSON label and at most 100000000 original bytes. Its original
buffer is admitted before I/O and allocation. The shared metadata budget also
charges decoded strings and vector growth, including freed temporary values.
Allocations remain fallible; allocator overhead and one bounded snapshot chunk
are separate. The returned object retains mapping metadata, not the original JSON.

The fixed JSON grammar requires exactly metadata and weight_map. Metadata has
one unsigned u64 total_size and string-only other annotations. The nonempty
mapping assigns unique decoded tensor names to exact safetensors basenames.
Duplicate keys reject at all object depths, including differently escaped forms.
No normalization occurs. Multiple tensors may use the same shard; its actual
contents and the complete expected file set remain package obligations.

The new mapping reader shares File's basename validation. Source/Assets regression
tests preserve existing canonical metadata behavior. Index JSON may have leading
whitespace, and integer -0 remains zero; original SHA-256 includes every byte.
No reconstructed JSON object replaces that identity.

The independent fixture generator calls only shards.parse_index. Its 81 cases
contain 43 valid and 38 invalid indices, including seeded mappings, Unicode,
maximum basenames, full u64 declared totals and multi-chunk original indices.
Tests compare all entries and total_size, reject insufficient aggregate metadata
budgets, and detect mutation in the last original byte even when it is padding.
The full u64 total is a declaration, not evidence for a payload of that size.

## Workflow 03

1. SourceIndex and SourceIndexEntry implement source §2's strict index structure.
2. No challenge or transcript order changes.
3. No tensor view or proof claim escapes. The complete package must independently
   check actual shards and selected/alias/ignored tensors before returning views.
4. Native controls reject duplicate keys, field/number/label changes and replayed
   byte mutation. No assigned production NC id is marked complete.
5. Original reads use the existing snapshot SHA-256 inventory. No new hash family,
   loss formula, profile budget or source authority is introduced.
6. No arithmetic certificate changes; total_size cannot authorize a runtime fit.
7. The entire index is parsed with exact EOF. Shard coverage and recomputed total
   remain mandatory; no claimed total is accepted as evidence for actual bytes.
8. Exact original bytes determine SHA-256; sorted decoded names determine lookup
   order without changing any canonical Source or Assets frame.
9. Every fixture matches the independent parser's mapping or specified native
   rejection. Original named-model, inference and proof parity are not claimed.
10. Parsing remains preparation T_misc; no measured constant or online weight pass.
11. The crate remains no_std and forbids unsafe code. JSON has fixed grammar depth,
    a bounded original buffer and explicit fallible metadata admission.
12. File, index, shard, tensor, mapping and total_size terminology is retained.

I tried to break it by changing the last original index byte after hashing, and
the control rejected it with SnapshotData before returning a mapping. This
same-author review does not approve the unfinished E5-03 task PR.
