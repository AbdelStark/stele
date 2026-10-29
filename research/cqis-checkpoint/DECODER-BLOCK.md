# Q26: complete dense decoder block

Question: do the selected exact operations compose into one Llama-style block,
with identical full causal and incremental outputs, without losing weight,
activation or gated-product units? Cost terms: T_witness/c_a/c_x/T_misc. Kill
criteria: an independent arithmetic mismatch, a full/cache difference, silent
int16 truncation of the int32 gate product, changed source/scale association,
or publishing a partial cache after a rejected output. Research only; no proof
admission, native forward, checkpoint fidelity or completion of E5-04.
