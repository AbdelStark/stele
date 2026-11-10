# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0", "numpy==1.26.4", "safetensors==0.6.2",
#                 "sentencepiece==0.2.0", "torch==2.5.1"]
# ///
"""RFC-0026 task E16-20: llama2.c `stories110M` through the development prover.

Karpathy's llama2.c `stories110M` (MIT; dim 768, 12 layers, 12 heads, hidden 2048, vocab 32000,
RMSNorm eps 1e-5, RoPE theta 10000, SwiGLU, shared embedding/classifier), trained on TinyStories.
The pipeline, CQIS configuration and commands are those of `stories42m.py` at this shape; only
the shape and the pinned digests differ. At T = 64 the head matmul has 6 + 15 + 10 = 31 bits,
so it is split into two row blocks (RFC-0026 A6).

Run from the repository root:
  uv run --script research/cqis-model-contract/stories110m.py convert <downloads> <source>
"""
import sys

import stories42m as s

s.BIN = 'stories110M.bin'
# https://huggingface.co/karpathy/tinyllamas (MIT), revision 0bd21da7698eaf29a0d7de3992de8a46ef624add.
s.INPUTS = {
    'stories110M.bin': '515267168726a1ed1317a64a408492e6af3b67c1f71c5bd98c01d9d721803a24',
    'tokenizer.model': '9e556afd44213b6bd1be2b850ebbbd98f5481437a8021afaf58ee7fb1818d347',
}
s.OUTPUTS = {
    'config.json': '3d9c7d3d609f1534397f57a1ebb9bbe24fd35442cb1355f59582e3be790e7332',
    'model.safetensors': 'da329b147eb5f2046089d08ea375a652e9b9898bd94e387ca37a4b3482744271',
    'tokenizer.model': '9e556afd44213b6bd1be2b850ebbbd98f5481437a8021afaf58ee7fb1818d347',
}
s.FRAMES = {
    'model.bin': '38db6c1ce9e49e4b68b45bcc894c4e15b05dbbce7e2b02a582a586e4819b5016',
    'preparation.bin': 'a8b616f3190ac169d4f801c978ac2e28e0faa00e4537d9f80e32c6dd19bab92a',
    'source.bin': 'd47199dc95fa42caf393db36dd138cbdf5c536d523ca0a28ff761bcb994a0dc2',
    'assets.bin': '36b3c78c4efc57776d35dda777f7fd0394cdd55d133555280f1ffe542cdae4b9',
}
s.PREPARED = {
    'artifact.bin': '83b126b082d8595bd096dab48a6e86e175593bb920900a73edce0b0eaf6c5df5',
    'scales.bin': '44c600cdfabe216a6f4d6479a8bbc2fdd27552b47f112bc0e554c75e37b9c019',
}
s.DIM, s.HIDDEN, s.LAYERS, s.HEADS = 768, 2048, 12, 12
s.CONFIG = s.CONFIG | {'hidden_size': s.DIM, 'intermediate_size': s.HIDDEN, 'num_hidden_layers': s.LAYERS,
                       'num_attention_heads': s.HEADS, 'num_key_value_heads': s.HEADS}

if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('assertions must remain enabled')
    {'convert': s.convert, 'frames': s.frames, 'fidelity': s.fidelity}[sys.argv[1]](*sys.argv[2:])
