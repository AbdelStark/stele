# Masked attention maximum bounds — Q26 research

Status: Draft RFC-0004 A3/A6 and RFC-0009 A2 evidence, retaining RFC-0009 A1's
attained unmasked maximum and full exponential domain. E5-03 stays blocked;
all original acceptance criteria and NC-0109 remain unchanged.

Question: can a static schema enforce the first attained allowed maximum and
nonnegative score differences without int32/M31 aliases, including sparse
absolute positions and masked scores? Security property: static integer
faithfulness and canonical mask/selection behavior. Cost term: T_attn/c_x;
no measured constant or proof-consumer claim.

Kill criterion, stated before implementation: drop the candidate if a modular
alias admits an unattained maximum, false difference or later tied key; if
bounds depend on actual data; or if it disagrees with the independent integer
and NumPy references. Source/mask/position ownership and function/range proof
consumers remain required beyond conditional numerical checks.
