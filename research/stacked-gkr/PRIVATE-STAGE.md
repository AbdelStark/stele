# Private coefficient stage composition (Q20)

Status: research. RFC-0006 A4 stays Draft and E3-06 stays blocked with every
original acceptance criterion. No private PCS or joint ZK construction is admitted.

Question: can the real stacked A1 coefficient final be consumed by the weighted
selection reduction at the restored canonical point, without source values in the
stage descriptor, while retaining every original tensor and source-bit obligation?
Security properties: fixed expected source/view, exact claim/point consumption,
complete original consumption and shared transcript continuation. Cost terms:
c_sc/T_misc, dense reference preparation and actual original consumers. Kill
criterion: source values in the descriptor, a discarded final, wrong-coordinate
acceptance by actual reference consumers, mismatched accounting or continuation.

The reference study will bind distinct source-view metadata before stage challenges,
restore both elimination orders, and consume all originals against separately
fixed public fixture data. Its messages remain unmasked. Dense stage preparation
is charged explicitly; sparse execution and real private consumers remain required.
