# Explicit model execution dependencies — Q26

Status: Draft RFC-0004 A3/A10 research, with RFC-0005 A1 semantic references.
E5-03 remains blocked with its original criteria. This is a numerical execution
graph, not the canonical Tensor IR plan, an authenticated private source resolver
or a production proof consumer.

Question: can the complete dense candidate execute from explicit operation input
references, physical weight/gain sources and configured function references,
while covering each existing arithmetic template exactly once? Security properties
are source-role completeness and operation ownership. Cost terms are T_misc and
T_witness; no performance number, cut or weight-pass change is proposed.

Kill criterion, before implementation: reject the design if a supplied edge,
physical source, function, shape or bound reference can replace the expected
configuration; if a tied head creates a second physical source; if an operation
reads a data operand outside its declared dependencies; or if numerical execution
disagrees with the independent full-model oracle. Reuse the existing configuration
and artifact loader, canonical function identities and arithmetic templates.

The graph will expose wide rows and row-conversion bundles, physical matrices and
gains, token/position inputs, every norm/projection/residual/activation/product and
the final head/first-maximum operation. A row bundle contains its codes, scale and
fraction together; it is not a single tensor identity in the future proof plan.
Projected attention remains a named composite with explicit Q/K/V, absolute
positions and generated RoPE inputs. Its internal head/GQA/mask/range/branch/index
lowering and actual proof consumers remain mandatory. The greedy operation returns
one decision per evaluated row, not a full generation/stopping statement.

Expected configuration bytes alone derive the graph and operation parameters.
Expected artifact bytes supply learned values through the existing checked loader.
A supplied graph must match the complete regenerated encoding before execution.
All node inputs must precede their consumer. Every existing bound family/role and
all 4L+1 function roles must occur once, including numerically identical roles.
The execution checker will compare every residual cut, final norm/row/logit and
first-maximum result with the existing oracle; controls will rebuild valid framing
after swapping same-shaped sources, edges, roles, function references and bindings.

No random challenge, claim, extension-field relation or ledger term is introduced.
Public numerical replay is not ZK, succinct verification, source-to-checkpoint
provenance or PCS authentication. Accepted RFCs remain unchanged.

## Derivation and encoding

`derive` uses the checked Config, never supplied graph data. A node has exactly
role, kind, layer, shape, inputs, source, function and bounds fields. Closed role
names identify operations, not physical checkpoint names. A physical node carries
the complete existing canonical Spec as lowercase hex; rotation nodes carry their
exact descriptor or the empty absent-rotation marker. Other source fields are empty.
Function references carry the operation role, FunctionId and RepresentationId.
Bounds are family-id/role pairs in the existing twelve-family collection.
This associates template ownership, without generating a new schema or claiming
that a symbolic reference enforces that template's integer relations.

There are 27L+9+U nodes, where U is one for an untied head and zero otherwise,
at most 3466. Each layer has nine physical sources, one rotation source and
seventeen numerical operations. The tied head reads physical.embedding directly.
The two residual additions take their precise cut/mid and projection inputs;
the gated product reads up and SiLU output, not the gate's preactivation.
Attention reads Q/K/V, canonical positions and its configured rotation rows.
The graph retains every 25L+B+5 arithmetic role and 4L+1 function role once.

Shapes describe numerical containers at configured context capacity, not padded
hypercube layouts. Matrix/gain shapes are the exact physical dimensions. Wide
rows and row bundles use context/width; bundles also own their row scale and units.
A rotation node's context axis indexes rows whose pair count is fixed by its
descriptor; absence supplies empty rows. Only the actual validated sequence prefix
is evaluated. This format supplies no padding, valid-row or private-index proof.

The evidence encoding is ASCII `stele/research/q26/model-flow/v1` plus NUL, the
32-byte separately expected config identity and a compact ASCII JSON node array.
Object keys are sorted, separators are comma/colon with no spaces, and arrays
retain derivation order. Integers are exact; no float, extension field or unknown
key is emitted. This is not `plan.json`, a replacement cqis_id or a passport.
Validation type/cap checks the supplied bytes, regenerates the complete expected
encoding and compares every byte. It does not parse supplied nodes into authority.

The 16 MiB cap is conservative: at most 3466 entries, each below 4096 bytes,
plus array separators and the fixed prefix. Physical Spec bytes are at most 512;
hex expansion, at most five inputs, eleven bound references, one function reference
and the closed name/shape fields all fit that per-entry envelope. No tensor data
is allocated from these context/width declarations during metadata derivation.
Execution separately applies the existing loader, model-token and full-block
workspace limits before numerical work.

## Executed dependencies and tests

`execute` checks an optional supplied encoding before loading learned values from
the separately expected artifact digest. Omitting that encoding derives the same
expected graph internally. It accepts no replacement node, data environment,
source callback or evaluator. Only physical nodes read learned matrices/gains;
arithmetic operations read their declared operands and configured scalar choices.
The interpreter calls the existing integer primitives, with projected attention
as an explicit composite. A per-operation function scopes temporary caches. Input
values are released after their last graph consumer, except residual cuts and
final outputs retained for comparison. The already loaded model remains resident.
This is numerical replay, with no streaming prover or one-pass performance claim.

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py
--model-flow`, or `--model-flow-controls`. The first invocation preceded the CLI
branch and rejected its unknown argument; after adding the branch, the tests
failed with ModuleNotFoundError before implementation. The independent graph
inspection checks topology, exact physical source Specs, all key projection/norm/
residual/product dependencies, logical shapes and complete bound/function coverage.
Its separate JSON frame builder shares the standard JSON library; inner
configuration codecs, existing family-role oracle and function identities are
shared and disclosed. Numerical comparison uses the existing independent
Fraction-based full-model oracle, with its certified nonlinear primitives shared.

Seed2662 covers 1000 configurations and 63473 nodes. The first 100 configurations
produce 94 matching full numerical results and six matching overflow rejections.
The frozen encoding checksum is
`8abf2b21a816ac8ce403a6556a705c7a7647fc949329406ee43232642b1753ce`.
A 128-layer tied case has 3465 nodes and 804973 bytes; the untied metadata case
exercises all 3466 nodes. These counts and bytes are correctness evidence, not
benchmark results. Full maximum-layer numerical execution is not claimed.
Thirty additional seed2666 models pass with distinct Q/K/V, norm, projection,
residual, gated-product and final units, plus distinct static scale policies.
These cases exercise the interpreter's scalar-parameter routing when equal
defaults would hide a mistaken choice.

Controls rebuild correctly framed JSON after replacing same-shaped Q/K weights,
norm gains, residual edges, attention Q/K inputs, product factors, source Specs,
function references, template ownership, shapes and layer ids. Omission,
duplication, order changes and 255 byte mutations reject with Flow. Digest,
Identity, ArtifactDigest, Capacity, Token and Length checks reject bad expected
inputs before their dependent work. Numerically equal gain-role swaps and alternate
exp representations still have distinct expected graphs. Changing valid gain bytes
cannot retain an old expected artifact digest. These earn no production NC credit.

The pinned baseline has 64 nodes and a 15315-byte encoding, SHA256
`a8af4a4c4fa3c43541b2be39c69cb731797ea65b89257230783d835a79454fe3`.
Execution through the graph agrees on every cut, final norm, row conversion,
logit and first-maximum result across the fixed six-token continuation. Full/cache/
greedy replay and the inherited native manifest/norm comparisons pass. All prior
fixture fields, including the separate block-variant evidence, remain unchanged.
The new graph identity describes the baseline configuration only.

## Remaining contract

Continue Q26 with expansion of the attention/row composites, exact stacked tensor
identities/views, padding and source/range/branch/index consumers. Bind every
integer relation to actual reduction inputs, then close the verifier-owned plan's
table code/tree/root choices and private PCS/virtual claim consumers. This study
does not replace Q20's source resolver or accept its bit-source representation.
Native full-model parity, supported architectures, fidelity, generation stopping
and private PCS/ZK/FS remain required. Metadata and replay contribute T_misc and
T_witness; no measured constant, new commitment, soundness line or cut changes.
