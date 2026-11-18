# E20-20 live lookup tree review

Reviewer codex-source-visits, lane Z. Accepted the field and reduction implementation at 5f80428e and the CUDA route at 82b89fe7 for development-tier hardware qualification under RFC-0014 A6.

At GKR level k the four retained projections visit level k+1 in the original component and side order. For each factor the device loads the pair at heap offset (2·2^k−1)+2·(i mod 2^k)+side and reads the selected component. This preserves the original repeated projection across the leading selector coordinate. The separate vanishing mask uses the full GKR coordinate and the checked construction verifies the declared degree and shape.

The lookup factors use each proof-local original owner’s physical row stride, logical data-quadrant extent, actual signed shift, public selector and padded table denominator. The reduction checks each top denominator before committing the top. A first-and-leaf lookup consumes its top without allocating a second tree. For longer descents, the last nonleaf constructs its four field factors and synchronizes before the owner is dropped. The leaf then requires the retained tree to have been released.

The complete proof corpus, required fault controls and the balanced T32 proof qualify the normal hardware path separately.
