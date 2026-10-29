# Q26: projected attention, GQA and absolute cache positions

Question: can one exact candidate compose Q/K rotation, row scales, score units,
GQA, restored V units and output assembly with identical full/cached results?
Cost terms: c_x/c_a/T_misc; security properties: source/scale/head association,
mask and position scope. Kill criteria: oracle disagreement, head-local scale
substitution, wrong GQA group, lost absolute block position or partial output on
an overflow. Prototype only; no native inference or proof admission.

The inputs are projected wide Q/K/V rows and explicit integer rotation tables.
Canonical table generation/identity, checkpoint projections and model fidelity
remain required; supplied coefficients do not establish a RoPE configuration.
