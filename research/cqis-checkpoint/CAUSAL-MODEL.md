# Q26: complete causal numerical model

Question: can the exact decoder blocks compose with embeddings, final norm,
vocabulary projection and greedy stopping, while preserving all row/channel
units and full/cache equality on both synthetic models and a pinned checkpoint?
Cost terms: T_witness/c_a/c_x/T_misc. Kill criteria: oracle disagreement, tied
weight reinterpretation, inconsistent layer units, a non-lowest argmax tie,
incorrect stopping or a partially advanced cache after failure. Research only;
native GPT-2/Llama parity, fidelity and the private proof remain required.
