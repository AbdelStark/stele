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
