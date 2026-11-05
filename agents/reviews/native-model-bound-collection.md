# Native complete Bounds collection — E5-03

Same-author `cqis-numerics` and `soundness-auditor` review of RFC-0025's
collection §§1–4. `model::Bounds` now derives the complete ordered collection
from immutable checked Model, Scales and fully regenerated Registry objects.
The remaining source conversion, assigned controls and original-model delivery
criteria still prevent completion of E5-03.

Scales and Registry must name the exact Model before any output is emitted.
No public constructor accepts an opaque Registry digest or caller-selected
record parameters. The collection header retains all three complete identities.
Changing a nonmaximum channel mantissa leaves the arithmetic records unchanged
but changes the collection identity, as the test checks explicitly.

Physical slots come first in Model order. The private resolver selects each
matrix and its own scales, plus its independently configured GPT-2 bias. The
head selects token record zero for GPT-2 and the separate head for Llama. Every
layer retains its prescribed operations, including repeated identical records.
Score passes its successfully derived bound to Maximum. Weighted and Normalize
use the same parameters, including full context and the full 1024-slot block
admission predicate. The incoming residual fraction advances only at the layer
boundary; normalization, activation, gated-product and projection units retain
their exact Model joins.

The producer holds one complete arithmetic record at a time. Expected counts
derive from the checked shape and decoding mode; running length uses checked
u64 addition against 512 MiB. No supplied length or count sizes an allocation.
Public validation compares the entire expected stream and requires exact EOF.
Short reads accumulate in a fixed buffer. A reader failure, excess read count,
truncation or suffix rejects; a sink failure returns no completed Bounds.
Only complete emission or validation returns the final identity and length.

Independent reference fixtures cover complete GPT-2 and Llama collections in
both decoding modes, plus invalid worst-score and short-context block cases.
Their Registries undergo native full data regeneration before collection tests.
Each prescribed slot is checked for its schema, parameters and complete record
digest; each slot is also corrupted, omitted and duplicated. Header mutations,
reordering, wrong input identities, nonmaximum scale changes, I/O failures and
length/cap boundaries are rejected at their stated boundary.

Separate private layout tests cover original GPT-2-small/Llama-3.1-8B dimensions
and both maximum shapes, with 481, 1164, 5005 and 4620 records respectively.
They derive every record and compare the ordered stream digest. They construct
neither a Registry nor a completed Bounds and grant no named-checkpoint source,
inference, fidelity, proof, privacy, profile or performance credit. The existing
full named-geometry Registry qualifications retain their separate scope.

## Workflow 03

1. Bounds constructors, streaming methods and identity accessors implement
   collection §§1–4. All nineteen existing arithmetic schemas remain unchanged.
2. No random challenge, transcript absorb or challenge order changes.
3. No proof claim is emitted. Actual range, arithmetic, branch, lookup and source
   consumers remain required by the Accepted consumer inventory.
4. Tests exercise every collection slot and each input identity join. They do
   not mark any assigned NC id or proof-level claim-graph edge complete.
5. No soundness-ledger line changes: no new random challenge or query exists.
6. Every record is static and derives from complete Model, Scales and Registry.
   Runtime activations, observed codes and actual request lengths are absent.
7. Full context and all prescribed operation slots remain present. Actual
   padding selectors and inactive lookup exclusion remain consumer obligations.
8. Shape order, exact integers and fixed descriptor fields determine every byte.
   There is no hash-map iteration or timing-dependent reduction.
9. Complete native/reference collection parity passes for the stated fixtures.
   GPU proof-byte parity and original-checkpoint inference are not claimed.
10. Derivation remains preparation T_misc. No online weight pass or measured
    cost-model constant changes; no performance result is asserted.
11. The crate remains `no_std`. Record allocation remains bounded and fallible;
    supplied counts and lengths cannot drive iteration or whole-frame storage.
12. Existing Model, Scales, Registry, Bounds and physical-role vocabulary is used.

I tried to break it by changing each slot, omitting and duplicating records,
substituting input identities, truncating streams and violating static attention
admission, and the control tests rejected it at the specified boundaries.
This same-author review does not approve the unfinished E5-03 task PR.
