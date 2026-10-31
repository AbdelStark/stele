# Native source preparation

`PreparedSource` builds the canonical RFC-0010 A9 prover material from an exact
row-major M31 matrix. Each row passes through the existing Circle encoder.
The constructor transposes its full encoded word into the column buffer, then
builds the actual RFC-0012 Merkle tree with descriptor Columns(id,N,4R).
Only one row's encoding and scratch are live at a time.

The original message remains immutably borrowed for later row functionals.
Prepared storage owns the column bytes and Merkle nodes. An individual response
borrows one payload and owns its complete bottom-up path. Repeated requests
produce separate full paths; no query sampler or deduplication is supplied here.
The context includes the selected QM31/OM31 degree, even though both use the same
M31 message encoder. Construction authenticates no externally supplied claim.

All matrix dimensions are exact. Wrong message lengths reject before allocation.
Checked products bound the column buffer, leaf-reference array and digest tree;
the encoder retains its own complete capacity checks. Allocations are fallible.
Invalid indices reject before path allocation or slicing. Encoder and Merkle
errors retain their causes. The caller-owned hash counters remain observable on
construction failure; a successful preparation counts all 2N-1 tree hashes.

The successful preparation reports borrowed input bytes separately from owned
vector capacities. Its peak is column storage plus the larger of:

- the measured full encoder peak, including output, twiddles and scratch;
- the live leaf-reference array plus Merkle digest-vector capacity.

Stack values, allocator metadata and process memory are excluded. Individual
response path allocations occur after preparation and belong to their consuming
operation's resource report. These are observations from the executed producer,
not estimates of a complete PCS proof or benchmark measurements.

Both-field tests reproduce all six independent full-wire fixtures. Every generated
column and path occurs in the oracle's certificate responses and authenticates
against its expected root. A changed message element fails against that root.
Controls reject extra or missing matrix elements, unsupported sources, invalid
indices, capacity overflow and hash-counter overflow. A compile-fail check
prevents mutation of the borrowed message while preparation remains in use.

Run `cargo test -p stele-pcs --locked --offline` and
`python3 -m unittest discover -s scripts/tests -p test_field_source_gate.py -v`.
The actual gate requires all preparation tests and all three compile-fail
boundaries. It also rejects added accepting methods or trait conversions inside
the existing preparation module. This remains a narrow regression guard, not
a semantic Rust sandbox.

The API creates no verified certificate, functional-opening receipt or NC credit.
Certificate/opening construction and verification, actual A1 closure and complete
resource/benchmark evidence remain part of E4-03a. No measured cost constant,
new committed tensor or matmul weight-pass change is claimed.
