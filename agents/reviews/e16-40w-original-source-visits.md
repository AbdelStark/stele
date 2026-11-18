# E16-40w source visit review

The integration-path reviewer inspected the disposable T32 source observer at
`81122240` against `238209a1`, then accepted the exact transfer accounting at
`51166128`. The ordinary prover selects each query through its existing
transcript and emits the canonical certificate or opening bytes. The observer
reads this completed response block, compares the GPU root, salted payload and
every sibling, and synchronizes the device before releasing the serial visit.
The private salt seed and original message stay inside the prover process.
The verifier and its one-opening budget checks retain their existing inputs.

The receipt reconstructs the message and metadata upload from the source
geometry. This includes both twiddle arrays, eight key words, sixteen salt
block words and the two descriptor prefixes. It also reconstructs the encoded
column allocation, retained Merkle levels, upload overlap, root readback and
every selected response readback. The controls exercise a missing visit and
an upload off by one byte. CUDA pool counters cover allocator overhead in
addition to the planned live-buffer footprint.

The CPU preparation baseline is the union of observed intervals, preserving
the overlap of the two small sources prepared concurrently. The device cost
counts both source visits, serialized on one H100. Mutex wait and overlap with
other proof work are orchestration costs outside that stage comparison.
Certificate and opening transcripts, row combinations and rank checks remain
CPU work. Whole-prover speedup and CPU/GPU proof parity require a separate
integrated run.
