# Weighted private selection composition (Q20)

Status: research. RFC-0006 A4 and E3-06 remain blocked; no private PCS or ZK
construction is admitted. All original task criteria remain required.

Question: can the private onehot reduction cover canonical multi-axis source
views, arbitrary category-axis placement, selected axes and broadcasting without
exposing the original index vector or allocating the category domain?
Security properties: exact MLE-of-Boolean-product semantics, expected source/view
identity, complete original consumption and transcript continuation. Cost terms:
c_sc/T_misc, source-view preparation and actual private consumers. Kill criterion:
any explicit-table mismatch, divide-by-zero exception on valid weights, omitted
original claim, source-layout alias or category-domain-sized candidate work.

The study will use public per-bit weights before extension, keep zero broadcast
factors and zero-sum weight pairs, and return every original bit claim in the
source view's canonical coordinate order. It remains an unmasked conditional
reduction; authentic bit/range/PCS and joint ZK consumers are still required.
