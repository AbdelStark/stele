# E16-40ai independent source review

Lane Z reviewed the research implementation at `12db612b` against `8986ce52` under RFC-0008 A7 and RFC-0013 A5. The occurrence origin uses the same source-local column offset and block ordinal as `Plan::block`. Each compact member carries the origin of its own `m*c+i` occurrence. The mask builder pairs that origin with its checked destination span even when the producer emits members in a different order.

Shared layer interpolation uses logical offset `D*stride+4*D*index`. A child selects the appropriate `2D`-entry half. The device maps each logical address to its physical row before combining low and high values at the actual line challenge. This covers halves that straddle physical rows. Window bounds, immutable owner identity and the required device are checked before the kernel reads the source. Its owner survives through synchronization.

The per-step receipt reconciles borrowed mask bytes against the preceding implementation's physical transfers. The independent source review accepts this implementation for its scoped hardware qualification.
