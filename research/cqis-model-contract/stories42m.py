# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0", "numpy==1.26.4", "safetensors==0.6.2",
#                 "sentencepiece==0.2.0", "torch==2.5.1"]
# ///
"""RFC-0026 task E16-11: a real trained Llama-architecture model for the development prover.

Karpathy's llama2.c `stories42M` (MIT; dim 512, 8 layers, 8 heads, hidden 1376, vocab 32000,
RMSNorm eps 1e-5, RoPE theta 10000, SwiGLU, shared embedding/classifier), trained on TinyStories.

  convert  IN OUT     check the pinned llama2.c files in IN; write the RFC-0025 Llama source
                      layout (model.safetensors, config.json, tokenizer.model) to OUT; check
                      the pinned output digests. The conversion is exact: fp32 values are copied,
                      Q/K rows are permuted from llama2.c's interleaved RoPE pairs to the HF
                      half-split layout (RoPE layout 1), and the shared classifier is written
                      as an explicit lm_head.weight (RFC-0025 Llama sources are untied).
  frames   OUT FR     write the Model, Preparation, Source and Assets frames for prepare_source.
  fidelity OUT PR [IN] fp32 reference vs the exact CQIS executor (harness cqis_torch, CPU) on the
                      prompt and on TinyStories windows; prints the greedy continuations and
                      the prove-dev arguments. Informative only, not a gate.

Run from the repository root:
  uv run --script research/cqis-model-contract/stories42m.py convert <downloads> <source>
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import sys

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for sub in (HERE, ROOT/'crates/stele-cqis/tests/support', ROOT/'harness/eval'):
    sys.path.insert(0, str(sub))

# https://huggingface.co/karpathy/tinyllamas (MIT), revision 0bd21da7698eaf29a0d7de3992de8a46ef624add;
# tokenizer.model from github.com/karpathy/llama2.c at 350e04fe35433e6d2941dce5a1f53308f87058eb.
INPUTS = {
    'stories42M.bin': '9f65a1000e17d0bc167dd6332e0ce5119a0222a3d920cead5bce413bfab2ee7b',
    'tokenizer.model': '9e556afd44213b6bd1be2b850ebbbd98f5481437a8021afaf58ee7fb1818d347',
}
OUTPUTS = {
    'config.json': '4a4b240bbf6dcaa546c2f91a3b4e1d031c17d69a238c7fd6a9eba57eb18e1db5',
    'model.safetensors': '8a18b4bd9a575c1cb2fd6108c8ae0fd3b09d31a68d2fdf977ccaaa44493b6f79',
    'tokenizer.model': '9e556afd44213b6bd1be2b850ebbbd98f5481437a8021afaf58ee7fb1818d347',
}
# https://huggingface.co/datasets/roneneldan/TinyStories (CDLA-Sharing-1.0), revision f54c09fd23315a6f9c86f9dc80f725de7d8f9c64.
VALID = '94e431816c4cce81ff71e4408ff8d3bda9a42e8d2663986697c3954288cb38b4'
# Frames written by `frames` and the prepare_source outputs the proof reads (SHA-256).
FRAMES = {
    'model.bin': '1931128e41f4464c4bae040ca3fef679f39ebd491258c15151b37b535c50b10c',
    'preparation.bin': '0531cd643cdd8f6e53ac00a36b61242b0cda2893908de7375a4b367ae207a46e',
    'source.bin': 'c35749520f51f4aeb7f98cef3a57385f212655004687addcb6f77f5ff0d722bb',
    'assets.bin': '1c5a6bbd7d06309944c6bd8c43a603c84430fab6c45de8b9ba6707a52562a174',
}
PREPARED = {
    'artifact.bin': '288a2f4afe96d5e3a67b95a448ce4b3964d2fe2f9a4c28c9ab745b62d91e41a4',
    'scales.bin': '873266cd4103a0f1a0f35c8d592c0507e0f7311657657860caf7c3297d50c4d8',
}
DIM, HIDDEN, LAYERS, HEADS, VOCAB, CONTEXT = 512, 1376, 8, 8, 32000, 1024
PROMPT = 'Once upon a time, there was a little girl named Lily. She loved to play outside in the park.'
GROUP = 128  # RFC-0004 A15 grouped rows on the d = 512 affine inputs


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_llama2c(path):
    """llama2.c legacy export: 7 int32 header words, then fp32 tensors in a fixed order."""
    raw = Path(path).read_bytes()
    header = np.frombuffer(raw, '<i4', 7).tolist()
    assert header == [DIM, HIDDEN, LAYERS, HEADS, HEADS, VOCAB, CONTEXT], header  # positive vocab: shared head
    f = np.frombuffer(raw, '<f4', offset=28)
    shapes = [('emb', (VOCAB, DIM)), ('rms_att', (LAYERS, DIM)), ('wq', (LAYERS, DIM, DIM)),
              ('wk', (LAYERS, DIM, DIM)), ('wv', (LAYERS, DIM, DIM)), ('wo', (LAYERS, DIM, DIM)),
              ('rms_ffn', (LAYERS, DIM)), ('w1', (LAYERS, HIDDEN, DIM)), ('w2', (LAYERS, DIM, HIDDEN)),
              ('w3', (LAYERS, HIDDEN, DIM)), ('rms_final', (DIM,)), ('freq_real', (CONTEXT, DIM//HEADS//2)),
              ('freq_imag', (CONTEXT, DIM//HEADS//2))]
    out, at = {}, 0
    for name, shape in shapes:
        n = int(np.prod(shape))
        out[name] = f[at:at+n].reshape(shape)
        at += n
    assert at == f.size, 'TrailingBytes'
    return out


def permute(w):
    """Meta/llama2.c interleaved RoPE rows -> HF half-split rows (transformers' convert script)."""
    return w.reshape(HEADS, DIM//HEADS//2, 2, DIM).transpose(0, 2, 1, 3).reshape(DIM, DIM)


def hf_tensors(w):
    t = {'model.embed_tokens.weight': w['emb'], 'lm_head.weight': w['emb'], 'model.norm.weight': w['rms_final']}
    for i in range(LAYERS):
        p = f'model.layers.{i}.'
        t |= {p+'input_layernorm.weight': w['rms_att'][i], p+'post_attention_layernorm.weight': w['rms_ffn'][i],
              p+'self_attn.q_proj.weight': permute(w['wq'][i]), p+'self_attn.k_proj.weight': permute(w['wk'][i]),
              p+'self_attn.v_proj.weight': w['wv'][i], p+'self_attn.o_proj.weight': w['wo'][i],
              p+'mlp.gate_proj.weight': w['w1'][i], p+'mlp.up_proj.weight': w['w3'][i],
              p+'mlp.down_proj.weight': w['w2'][i]}
    return {k: np.ascontiguousarray(v, dtype='<f4') for k, v in t.items()}


CONFIG = {
    'architectures': ['LlamaForCausalLM'], 'model_type': 'llama', 'hidden_size': DIM, 'intermediate_size': HIDDEN,
    'num_hidden_layers': LAYERS, 'num_attention_heads': HEADS, 'num_key_value_heads': HEADS,
    'max_position_embeddings': CONTEXT, 'vocab_size': VOCAB, 'hidden_act': 'silu', 'rms_norm_eps': 1e-05,
    'rope_theta': 10000, 'bos_token_id': 1, 'eos_token_id': 2, 'tie_word_embeddings': False,
    'torch_dtype': 'float32'}


def convert(src, out):
    from safetensors.numpy import save_file
    src, out = Path(src), Path(out)
    for name, digest in INPUTS.items():
        assert sha256(src/name) == digest, ('InputFile', name)
    out.mkdir(parents=True, exist_ok=True)
    save_file(hf_tensors(load_llama2c(src/'stories42M.bin')), out/'model.safetensors')
    (out/'config.json').write_text(json.dumps(CONFIG, indent=2, sort_keys=True)+'\n')
    shutil.copyfile(src/'tokenizer.model', out/'tokenizer.model')
    got = {n: sha256(out/n) for n in ('config.json', 'model.safetensors', 'tokenizer.model')}
    print(json.dumps(got, indent=1))
    assert got == OUTPUTS, 'OutputDrift'


def configuration():
    """CQIS family-1 Model and SourceMap: the Llama-3.1 qualification parameters at this shape,
    int8 matrices, grouped rows on the d-wide affine inputs, greedy decoding."""
    import qualify_original_llama as ql
    from model_codec import Rotation
    from rms_bounds import RMSNorm
    from source_map import SourceMap
    base = ql.base
    s = base.Shape(1, LAYERS, DIM, HEADS, HEADS, DIM//HEADS, HIDDEN, VOCAB, CONTEXT)
    norm = RMSNorm(DIM, 7, 8, 7, 1, 100000)
    rotation = Rotation(DIM//HEADS, CONTEXT, 0, 1, 0, ((10000, 1), (1, 1), (0, 1), (0, 1)))
    g = (2, GROUP)
    block = ql.Block(norm, norm, (7,)*7, 7, 7, 7, (g, (0, 0), (0, 0), (0, 0), g, g, (0, 0)), 1, -3, 0, 0,
                     base.Exponential(CONTEXT, 15, 7, 14, 0), base.Activation(HIDDEN, 1, 7, 7), rotation)
    formats = tuple((8, 0) if len(ds) == 2 else (16, 8) for _, _, ds in base.roles(s))
    model = ql.Model(s, formats, 7, (block,)*LAYERS, norm, g, 7, None)
    from random import Random
    m = base.mapped(model, 2, Random(0))
    mapping = SourceMap(m.shape, tuple(replace(e, dtype=3) for e in m.entries), (), ())  # dtype 3: F32
    return model, mapping


def frames(out, fr):
    import qualify_original_llama as ql
    base = ql.base
    out, fr = Path(out), Path(fr)
    fr.mkdir(parents=True, exist_ok=True)
    model, mapping = configuration()
    file = lambda n: base.sc.File(n, (out/n).stat().st_size, bytes.fromhex(sha256(out/n)))
    source = base.sc.Source(0, None, (file('model.safetensors'),))
    assets = base.sc.Assets(file('config.json'), (file('tokenizer.model'),), None)
    raw = {'model.bin': base.model_frame(model), 'preparation.bin': base.preparation(model, mapping),
           'source.bin': base.sc.encode_source(source), 'assets.bin': base.sc.encode_assets(assets)}
    for name, value in raw.items():
        (fr/name).write_bytes(value)
    assert {n: hashlib.sha256(v).hexdigest() for n, v in raw.items()} == FRAMES, 'FrameDrift'


def reference(t, tokens, interleaved=False):
    """fp32 forward of the converted weights (HF layout) or of the original llama2.c layout."""
    hd = DIM//HEADS
    x = t['model.embed_tokens.weight'][tokens].astype(np.float32)
    n = len(tokens)
    inv = 1.0/(10000.0**(np.arange(0, hd, 2, dtype=np.float32)/hd))
    ang = np.arange(n, dtype=np.float32)[:, None]*inv[None]
    cos, sin = np.cos(ang), np.sin(ang)

    def rms(v, g):
        return v/np.sqrt((v*v).mean(-1, keepdims=True)+1e-5)*g

    def rope(q):
        q = q.reshape(n, HEADS, hd)
        if interleaved:
            a, b = q[..., 0::2], q[..., 1::2]
            r = np.empty_like(q)
            r[..., 0::2], r[..., 1::2] = a*cos[:, None]-b*sin[:, None], a*sin[:, None]+b*cos[:, None]
            return r
        a, b = q[..., :hd//2], q[..., hd//2:]
        return np.concatenate([a*cos[:, None]-b*sin[:, None], b*cos[:, None]+a*sin[:, None]], -1)

    mask = np.triu(np.full((n, n), -np.inf, np.float32), 1)
    for i in range(LAYERS):
        p = f'model.layers.{i}.'
        h = rms(x, t[p+'input_layernorm.weight'])
        q, k = rope(h@t[p+'self_attn.q_proj.weight'].T), rope(h@t[p+'self_attn.k_proj.weight'].T)
        v = (h@t[p+'self_attn.v_proj.weight'].T).reshape(n, HEADS, hd)
        s = np.einsum('qhd,khd->hqk', q, k)/np.sqrt(hd)+mask
        s = np.exp(s-s.max(-1, keepdims=True))
        s /= s.sum(-1, keepdims=True)
        x = x+np.einsum('hqk,khd->qhd', s, v).reshape(n, DIM)@t[p+'self_attn.o_proj.weight'].T
        h = rms(x, t[p+'post_attention_layernorm.weight'])
        a = h@t[p+'mlp.gate_proj.weight'].T
        x = x+((a/(1+np.exp(-a)))*(h@t[p+'mlp.up_proj.weight'].T))@t[p+'mlp.down_proj.weight'].T
    return rms(x, t['model.norm.weight'])@t['lm_head.weight'].T


def nll(logits, tokens):
    z = logits[:-1].astype(np.float64)
    z = z-z.max(-1, keepdims=True)
    lp = z-np.log(np.exp(z).sum(-1, keepdims=True))
    return float(-lp[np.arange(len(tokens)-1), tokens[1:]].sum())


def windows(sp, text, count, length=64):
    """After the opening fragment, the first `count` stories with at least `length` tokens, each truncated to `length`."""
    out = []
    for story in text.split('<|endoftext|>')[1:]:  # the file opens mid-story
        ids = [1]+sp.encode(story.strip())
        if len(ids) >= length:
            out.append(ids[:length])
        if len(out) == count:
            return out
    raise ValueError('Windows')


def fidelity(out, pr, downloads=None, count=4):
    import sentencepiece
    from blake3 import blake3
    from safetensors.numpy import load_file
    import artifact_codec
    import model_codec
    import numpy_execution
    import cqis_torch
    out, pr = Path(out), Path(pr)
    for name, digest in (FRAMES | PREPARED).items():
        if name in ('model.bin', 'preparation.bin', 'artifact.bin', 'scales.bin'):
            assert sha256(pr/name) == digest, ('Prepared', name)
    t = load_file(out/'model.safetensors')
    sp = sentencepiece.SentencePieceProcessor(model_file=str(out/'tokenizer.model'))
    model_raw = (pr/'model.bin').read_bytes()
    model = model_codec.decode(model_raw)
    mapping = artifact_codec.decode_preparation(model, (pr/'preparation.bin').read_bytes())
    raw = (pr/'artifact.bin').read_bytes()
    ex = cqis_torch.Executor(numpy_execution.load(model, mapping, (pr/'scales.bin').read_bytes(), raw,
                                                  blake3(raw).digest()), 'cpu')
    unit = 2.0**-model.logits_fraction

    def cqis(tokens):
        return ex.full(tokens, keep_cuts=False)[1].double().numpy()*unit

    prompt = [1]+sp.encode(PROMPT)
    # The layout permutation is exact: the original llama2.c forward agrees with the converted one.
    valid = Path(downloads)/'TinyStories-valid.txt' if downloads else None
    assert valid is None or sha256(valid) == VALID, 'ValidationText'
    if downloads:
        w = load_llama2c(Path(downloads)/'stories42M.bin')
        orig = {k: v for k, v in hf_tensors(w).items()}
        for i in range(LAYERS):
            p = f'model.layers.{i}.self_attn.'
            orig[p+'q_proj.weight'], orig[p+'k_proj.weight'] = w['wq'][i], w['wk'][i]
        diff = np.abs(reference(orig, prompt, interleaved=True)-reference(t, prompt)).max()
        assert diff < 1e-3
    report = dict(prompt=PROMPT, prompt_tokens=len(prompt))
    if downloads:
        report['layout_check_max_abs_logit_diff'] = float(diff)
    for name, run in (('fp32', lambda ids: reference(t, ids)), ('cqis', cqis)):
        ids = list(prompt)
        while len(ids) < 64:
            ids.append(int(np.argmax(run(ids)[-1])))
        report[name] = dict(tokens=ids, text=sp.decode(ids[len(prompt):]))
    agree = next((i for i, (a, b) in enumerate(zip(report['fp32']['tokens'], report['cqis']['tokens'])) if a != b), 64)
    report['greedy_agreement_tokens'] = agree - len(prompt) if agree < 64 else 64 - len(prompt)
    if valid:
        ws = windows(sp, Path(valid).read_text(), count)
        for name, run in (('fp32', lambda ids: reference(t, ids)), ('cqis', cqis)):
            total = sum(nll(run(ids), ids) for ids in ws)
            report[name]['ppl'] = float(np.exp(total/sum(len(ids)-1 for ids in ws)))
        report['windows'] = dict(count=len(ws), length=64, sha256=sha256(valid))
    ids = report['cqis']['tokens']
    report['prove_dev'] = dict(tokens=','.join(map(str, ids)), checked=f'{len(prompt)-1}..64',
                               next=int(np.argmax(cqis(ids)[-1])))
    print(json.dumps(report, indent=1))


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('assertions must remain enabled')
    {'convert': convert, 'frames': frames, 'fidelity': fidelity}[sys.argv[1]](*sys.argv[2:])
