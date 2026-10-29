# Scoped model arithmetic record collection — Q26

Status: Draft RFC-0004 A3/A6–A10 evidence. All original E5-03 criteria and
blocked status remain unchanged. This is not a complete proof-plan contract.

Question: can the twelve existing arithmetic record families form one closed,
canonical collection derived from independently expected configuration and
artifact identities, without omission, duplication, reordering or adoption of
supplied record metadata? Security properties are complete scoped membership,
static authority and preservation of model/representation/source identity.
Preparation and collection validation belong to T_misc/T_witness.

Kill criterion, stated before implementation: drop this candidate if a legal
model role is omitted/deduplicated, a different source/configuration/representation
can reuse the same framed collection, runtime magnitudes tighten any record,
a supplied frame selects its own schema or identity, or resource limits depend
on untrusted record lengths. Do not claim source/table proof authentication.

Candidate: reconstruct the bounded numerical model using the existing loader
from separately expected configuration/artifact hashes, then derive every
unchanged record through its closed family adapter. Retain both expected hashes
in the collection. Runtime Model alone is insufficient because it loses physical
source labels, function representations and exact rotation descriptors. No
unvalidated artifact exponent or source-observed bound may choose a record.

The family order is scaled-linear, row, rotary, residual, greedy, attention sum,
attention normalization, attention block, attention score, attention maximum,
gated product, RMSNorm. Within each family retain its existing model-role order.
For L layers and B block-mode layers, count is 25L+B+5, at most 3333. Records
are keyed by family and role, since row/rotary query/key role strings overlap.
Identical bytes retain every role. All schemas remain unchanged; only RMSNorm
uses Accepted RFC-0022 bytes in this collection, the others remain Draft.

The intended frame is a distinct research domain plus expected config/artifact
hashes, u32 record count and entries containing u8 closed family id, u16 ASCII
role length/name and u32 record length/bytes, all little-endian. Cap each name at
64 bytes and record at 8192; the complete frame is bounded by 32 MiB. Validation
regenerates the expected collection and compares exact bytes, never parses a
supplied count into trusted roles. Existing loader preallocation limits remain.

The exact frame and tests will be fixed before publication. Function component
manifests/data roots, symbolic source/range/branch/index consumers and full plan
lowering remain separate. Config-selected function representations are preserved
by the expected config identity, not admitted as table bindings. RoPE's Draft
function definition must not be relabelled as an existing FunctionId. This work
introduces no challenge, loss, cut, proof weight pass or measured constant.
