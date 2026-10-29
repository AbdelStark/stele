# Attention score bounds — Q26 research

Status: Draft RFC-0004 A3/A6 and RFC-0009 A2 only. E5-03 remains blocked;
original acceptance and NC-0109 are unchanged. No production proof consumer.

Question: can scaled QK scores have closed static records and integer-faithful
relations across the full signed-int32 score range, including masked scores?
The security property is static field faithfulness. The cost terms at stake are
T_range/T_attention and certificate bytes; no measured constant changes.

Kill criterion, stated before implementation: drop this candidate if any
accepted policy admits distinct scores through an M31 alias, needs data-derived
caps, changes nearest rounding or cannot match independent integer/Fraction
and NumPy references. Keep unsafe static score policies rejected even at zero.
Whole-row conversion, rotary source, head/GQA/absolute-position ownership,
mask/max/function consumers, native parity and fidelity remain separate.
