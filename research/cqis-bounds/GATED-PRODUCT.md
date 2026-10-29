# Exact gated-product bounds — Q26 research

Status: Draft RFC-0004 A3/A8. E5-03 remains blocked; all original acceptance
criteria and NC-0109 remain unchanged. No admitted proof consumer.

Question: can the exact signed int16-by-int16 product be bound to both factor
sources before gated row conversion, without a modular alias or intermediate
requantisation? Security property: static integer faithfulness and source
association. Cost terms: c_a/T_witness; no measured constant changes.

Kill criterion, stated before implementation: drop this candidate if a false
product or coherent intermediate can pass through an M31 alias, if any bound
uses actual values, or if integer/NumPy references disagree. The product retains
units fu+E and the complete row conversion follows it. SiLU membership, factor
ownership and actual range/source consumers remain separate obligations.
