# Private selection coefficient question (Q20)

Status: research; RFC-0006 A4 and E3-06 remain blocked. No production behavior,
source authentication, zero-knowledge construction or catalog credit is added.

Question: can a onehot MLE claim reduce to original index-bit claims without
disclosing the complete selection vector or constructing its dense onehot table?
Security properties: original-source binding, exact index range and privacy of
witness indices. Cost terms: c_sc/T_misc, original index-bit consumers and their
range/packing relations. Kill criterion: any mismatch with the explicit Boolean
onehot table, unchecked original bit claim, degree above four, or work/storage
proportional to the category domain rather than the index-bit data.

The proposed study uses a binary product tree of affine index-bit factors and
degree-three A1 reductions. Every original bit claim must reach a real consumer;
the research reference consumer is not a private PCS or a ZK proof. Transcript
and resource accounting, zero coefficients, padding and non-power-of-two ranges
must be explicit before recommending any production amendment.
