"""E5-05 cloud runner (Modal): prepare the qualified Llama-3.1-8B CQIS Artifact, prove
torch/native parity on the E5-04 receipt, then score fp32 and CQIS on the same items.

  set -a; . ./.env; set +a          # HF_TOKEN, MODAL_TOKEN_ID/SECRET; never committed
  modal run harness/eval/modal_e505.py::prepare
  modal run harness/eval/modal_e505.py::parity
  modal run harness/eval/modal_e505.py::fidelity --tag fp32|cqis [--benchmarks ...]
  modal volume get stele-e505 results <local dir>

Without Modal installed (e.g. a rented GPU host with the repository at /root/stele and a
/vol directory), the same functions run in-process:
  python harness/eval/modal_e505.py fidelity --tag cqis-r24-f10-g128 --fraction 10 --residual_bits 24 --group 128

Every input is pinned: the original files by the E5-03c receipt hashes, the Artifact by
its receipt SHA-256, and the native execution by the E5-04 output SHA-256.
"""
import json
import os
from pathlib import Path

try:
    import modal
except ImportError:  # plain host: the decorators are no-ops and /vol is a local directory
    modal = None

_here = Path(__file__).resolve()
ROOT = _here.parents[2] if len(_here.parents) > 2 else _here.parent  # container imports from /root
REPO = '/root/stele'
if modal is None:
    class _Local:
        def function(self, **_):
            return lambda f: f

        def commit(self):
            pass
    app = volume = _Local()
    secret = image = None
else:
    app = modal.App('stele-e505')
    volume = modal.Volume.from_name('stele-e505', create_if_missing=True)
    secret = modal.Secret.from_dict({'HF_TOKEN': os.environ.get('HF_TOKEN', '')})
    image = (
        modal.Image.debian_slim(python_version='3.12')
        .apt_install('curl', 'build-essential', 'pkg-config', 'git')
        .run_commands('curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.90.0 --profile minimal')
        .pip_install('torch==2.5.1', 'numpy==1.26.4', 'blake3==1.0.11', 'python-flint==0.9.0',
                     'safetensors==0.6.2', 'transformers==4.46.3', 'accelerate==1.1.1', 'datasets==3.1.0',
                     'huggingface_hub==0.26.2', 'lm_eval==0.4.5', 'langdetect==1.0.9', 'immutabledict==4.2.1',
                     'nltk==3.9.1', 'pyarrow==17.0.0')
        .env({'HF_HOME': '/vol/hf', 'PYTHONUNBUFFERED': '1'})
        .add_local_dir(ROOT, REPO, ignore=['target', '.git', '.env', '**/__pycache__', 'bench/out'])
    )
SOURCE, PREPARED, RESULTS = Path('/vol/llama'), Path('/vol/prepared'), Path('/vol/results')
RECEIPT = 'agents/reviews/e503c-original-preparation/llama-int8.json'
EXECUTION = 'agents/reviews/e504-native-execution/llama-int8.json'


def _paths():
    import sys
    for sub in ('harness/eval', 'crates/stele-cqis/tests/support', 'research/cqis-model-contract'):
        sys.path.insert(0, f'{REPO}/{sub}')


def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(1 << 24):
            h.update(chunk)
    return h.hexdigest()


@app.function(image=image, volumes={'/vol': volume}, secrets=[secret], cpu=16, memory=65536, timeout=4*3600)
def prepare():
    import subprocess
    from huggingface_hub import snapshot_download
    _paths()
    import qualify_original_llama as ql
    base = ql.base
    receipt = json.loads(Path(REPO, RECEIPT).read_text())
    snapshot_download('meta-llama/Llama-3.1-8B', revision=ql.REVISION, local_dir=SOURCE,
                      allow_patterns=list(ql.PINS), token=os.environ['HF_TOKEN'])
    for name, expected in ql.PINS.items():
        assert _sha256(SOURCE/name) == expected, ('OriginalFile', name)
    checked = {n: base.sc.File(n, (SOURCE/n).stat().st_size, bytes.fromhex(h)) for n, h in ql.PINS.items()}
    model, mapping = ql.configuration(8)
    source = base.sc.Source(1, checked['model.safetensors.index.json'],
                            tuple(checked[n] for n in sorted(ql.PINS) if n.endswith('.safetensors')))
    assets = base.sc.Assets(checked['config.json'], tuple(checked[n] for n in
                            ('special_tokens_map.json', 'tokenizer.json', 'tokenizer_config.json')), checked['generation_config.json'])
    frames = {'model.bin': base.model_frame(model), 'preparation.bin': base.preparation(model, mapping),
              'source.bin': base.sc.encode_source(source), 'assets.bin': base.sc.encode_assets(assets)}
    inputs = Path('/vol/inputs')
    inputs.mkdir(exist_ok=True)
    for name, raw in frames.items():
        (inputs/name).write_bytes(raw)
        assert _sha256(inputs/name) == receipt['artifacts'][name], ('Frame', name)
    env = dict(os.environ, CARGO_TARGET_DIR='/vol/target', PATH=f"/root/.cargo/bin:{os.environ['PATH']}")
    subprocess.run(['cargo', 'build', '--release', '--locked', '-p', 'stele-cqis', '--example', 'prepare_source'],
                   cwd=REPO, env=env, check=True)
    if not PREPARED.exists():
        subprocess.run(['/vol/target/release/examples/prepare_source', *(str(inputs/n) for n in frames), '2',
                        str(SOURCE), str(PREPARED)], check=True)
    for name in ('artifact.bin', 'scales.bin', 'model.bin', 'preparation.bin'):
        target = PREPARED/name if (PREPARED/name).exists() else inputs/name
        assert _sha256(target) == receipt['artifacts'][name], ('Prepared', name)
    volume.commit()
    print(json.dumps(dict(status='prepared', artifact_sha256=receipt['artifacts']['artifact.bin'])))


def _executor(device='cuda', fraction=2, residual_bits=16, knobs=None):
    """The E5-04 runtime model (residual fraction 2, ADR-058) over the frozen Artifact;
    residual_bits=24 selects the RFC-0004 A14 wide model (rmsnorm_q version 2)."""
    assert residual_bits in (16, 24)
    _paths()
    from blake3 import blake3
    import artifact_codec
    import model_codec
    import scales_codec
    from execution_units import residual_units
    import numpy_execution
    import cqis_torch
    receipt = json.loads(Path(REPO, RECEIPT).read_text())
    original = model_codec.decode(Path('/vol/inputs/model.bin').read_bytes())
    model = residual_units(original, fraction, 2 if residual_bits == 24 else 1)  # 24: RFC-0004 A14
    if knobs:  # E5-05b configuration fractions; the codec checks every join
        import knobs as kn
        # shortcut: tables are evaluated (and rejected) lazily per used input; a full
        # registry_codec.encode takes hours in pure Python. Certify before any claim.
        model = kn.configure(model, **knobs)
    mapping = artifact_codec.decode_preparation(model, Path('/vol/inputs/preparation.bin').read_bytes())
    scales_raw = scales_codec.encode(model, scales_codec.decode(original, (PREPARED/'scales.bin').read_bytes()))
    execution = json.loads(Path(REPO, EXECUTION).read_text())
    if (fraction, residual_bits, knobs) == (2, 16, None):  # the qualified E5-04 runtime configuration
        assert blake3(model_codec.encode(model)).hexdigest() == execution['execution_model_id']
        assert blake3(scales_raw).hexdigest() == execution['execution_scales_id']
    raw = (PREPARED/'artifact.bin').read_bytes()
    expected = bytes.fromhex(receipt['native_result']['digest_cqis'])
    data = numpy_execution.load(model, mapping, scales_raw, raw, expected)
    ex = cqis_torch.Executor(data, device)
    import torch
    rotation = model.blocks[0].rotation
    assert all(b.rotation == rotation for b in model.blocks)
    cache = Path('/vol/rotation-4608.pt')
    if cache.exists():
        ex.rotation[rotation] = torch.load(cache).to(device)
    else:  # certify once; the cached table is derived data, regenerated from the definition
        ex.rotate(rotation, torch.zeros((1, model.shape.heads*model.shape.head_width), dtype=torch.int64, device=device),
                  torch.tensor([4607], device=device), model.shape.heads)
        torch.save(ex.rotation[rotation].cpu(), cache)
        volume.commit()
    return data, ex


@app.function(image=image, volumes={'/vol': volume}, gpu='H100', cpu=8, memory=98304, timeout=2*3600)
def parity():
    """Reproduce the E5-04 native output SHA-256 byte for byte, then time representative work."""
    import hashlib
    import time
    from struct import pack
    import numpy as np
    import torch
    data, ex = _executor()
    import numpy_execution
    from qualify_original_execution import decision_bytes
    oracle = numpy_execution.Oracle(data)

    def stream(tokens, result):
        cuts, logits, cache = result
        raw = bytearray()
        for cut in cuts:
            raw += cut.to(torch.int16).cpu().numpy().astype('<i2').tobytes()
        raw += logits.to(torch.int16).cpu().numpy().astype('<i2').tobytes()
        raw += pack('<I', len(tokens)) + pack('<'+'I'*len(tokens), *tokens)
        for k, v in cache:
            for t in range(k.codes.shape[0]):
                for rows in (k, v):
                    raw += pack('<IB', int(rows.scale[t]), rows.fraction) + rows.codes[t].to(torch.int8).cpu().numpy().tobytes()
        return bytes(raw)

    sequence, prompt, seed, eos = (128000, 9906, 11), (128000, 9906), bytes(range(32)), (128001, 128008, 128009)
    reference = bytearray(b'stele-e504-numerical-v1' + pack('<I', len(sequence)) + stream(sequence, ex.full(list(sequence))))
    generated, decisions, reason = prompt, [], 0
    result = ex.full(list(generated))
    for _ in range(2):
        token, decision = oracle.choose(result[1][-1].cpu().numpy().astype(np.int64), seed, len(generated))
        decisions.append(decision_bytes(len(generated), token, decision))
        generated += (token,)
        result = ex.full(list(generated))
        if token in eos:
            reason = 1
            break
    reference += bytes((reason,)) + pack('<I', len(decisions)) + b''.join(decisions)
    reference += pack('<I', len(generated)) + stream(generated, result)
    execution = json.loads(Path(REPO, EXECUTION).read_text())
    digest = hashlib.sha256(reference).hexdigest()
    report = dict(compared_bytes=len(reference), output_sha256=digest,
                  native_output_sha256=execution['output_sha256'], equal=digest == execution['output_sha256'])
    print(json.dumps(report), flush=True)
    assert report['equal'] and len(reference) == execution['compared_bytes'], report
    rng = np.random.default_rng(5505)
    timings = {}
    for n in (256, 1024, 4096):
        tokens = [128000] + rng.integers(1000, 120000, n-1).tolist()
        torch.cuda.synchronize(); t = time.time()
        try:
            ex.full(tokens, keep_cuts=False, head_rows=False)
            status = 'ok'
        except ValueError as error:
            status = str(error)
        torch.cuda.synchronize(); timings[f'full_{n}'] = (time.time() - t, status)
    t = time.time()
    out = ex.generate([[128000, 9906, 11]]*8, 32, [128001], batch=8)
    timings['generate_8x32'] = (time.time() - t, [r for _, r in out])
    report['timings_s'] = timings
    RESULTS.mkdir(exist_ok=True)
    (RESULTS/'parity.json').write_text(json.dumps(report, indent=2) + '\n')
    volume.commit()
    print(json.dumps(report), flush=True)


@app.function(image=image, volumes={'/vol': volume}, secrets=[secret], gpu='H100', cpu=8, memory=98304, timeout=12*3600)
def fidelity(tag: str, benchmarks: str = 'wikitext,arc,mmlu_pro,gpqa,ifeval', limits: str = '{}',
             fraction: int = 2, residual_bits: int = 16, group: int = 0):
    """group > 0 runs grouped activation rows (RFC-0004 A15) on every eligible row."""
    _paths()
    from transformers import AutoTokenizer
    import fidelity as fid
    tokenizer = AutoTokenizer.from_pretrained(SOURCE)
    if tag == 'fp32':
        backend = fid.Fp32(SOURCE)
    else:
        knobs = {'group': group} if group else None
        backend = fid.Cqis(_executor(fraction=fraction, residual_bits=residual_bits, knobs=knobs)[1])
    names = benchmarks.split(',')
    if 'gpqa' in names:
        try:
            fid.multiple_choice('gpqa')
        except Exception as error:  # gated dataset without granted access
            print(json.dumps(dict(skipped='gpqa', reason=type(error).__name__)), flush=True)
            names.remove('gpqa')
    fid.run(backend, tag, tokenizer, RESULTS/'items', names, {k: int(v) for k, v in json.loads(limits).items()},
            checkpoint=volume.commit)
    volume.commit()


@app.function(image=image, volumes={'/vol': volume}, gpu='H100', cpu=8, memory=98304, timeout=3600)
def profile(n: int = 1024):
    """cProfile one warmed-up pass, to find the throughput bottleneck."""
    import cProfile
    import pstats
    import numpy as np
    import torch
    _, ex = _executor()
    tokens = [128000] + np.random.default_rng(1).integers(1000, 120000, n-1).tolist()
    ex.full(tokens, keep_cuts=False, head_rows=False)
    torch.cuda.synchronize()
    p = cProfile.Profile()
    p.enable()
    ex.full(tokens, keep_cuts=False, head_rows=False)
    torch.cuda.synchronize()
    p.disable()
    pstats.Stats(p).sort_stats('tottime').print_stats(25)


@app.function(image=image, volumes={'/vol': volume}, secrets=[secret], gpu='H100', cpu=8, memory=98304, timeout=6*3600)
def ablation(configs: str = '16:3,16:4,16:5,24:8,24:10,24:12'):
    """Residual-path knob sweep (RFC-0004 §8) on fixed subsets: 8 WikiText windows, 300 ARC items."""
    _paths()
    from transformers import AutoTokenizer
    import torch
    import fidelity as fid
    tokenizer = AutoTokenizer.from_pretrained(SOURCE)
    for config in configs.split(','):
        bits, fraction = map(int, config.split(':'))
        backend = fid.Cqis(_executor(fraction=fraction, residual_bits=bits)[1])
        fid.run(backend, 'cqis', tokenizer, RESULTS/'ablation'/f'r{bits}-f{fraction}'/'items', ['wikitext', 'arc'],
                {'wikitext': 8, 'arc': 300}, checkpoint=volume.commit)
        del backend
        torch.cuda.empty_cache()
        volume.commit()
        print(json.dumps(dict(done=config)), flush=True)


@app.function(image=image, volumes={'/vol': volume}, secrets=[secret], gpu='H100', cpu=8, memory=98304, timeout=3600)  # $50 cap: one hour per sweep
def knob_sweep(configs: str, windows: int = 8, arc: int = 0):
    """E5-05b attribution: wide model (int24, fraction 10) plus one configuration knob set
    per entry of the JSON list [{"name": ..., "attention": 10, ...}], on fixed subsets."""
    _paths()
    import time
    from transformers import AutoTokenizer
    import torch
    import fidelity as fid
    tokenizer = AutoTokenizer.from_pretrained(SOURCE)
    for config in json.loads(configs):
        name, start = config.pop('name'), time.time()
        if 'act' in config:
            config['act'] = tuple(config['act'])
        try:
            executor = _executor(fraction=10, residual_bits=24, knobs=config or None)[1]
            executor.replay = False  # an ordered replay of an 8B rejection takes hours
            backend = fid.Cqis(executor)
        except ValueError as error:  # an illegal configuration (e.g. a table outside int16)
            print(json.dumps(dict(config=name, invalid=str(error))), flush=True)
            continue
        names, limits = ['wikitext'] + (['arc'] if arc else []), {'wikitext': windows, 'arc': arc}
        fid.run(backend, 'cqis', tokenizer, RESULTS/'knobs'/name/'items', names, limits, checkpoint=volume.commit)
        del backend
        torch.cuda.empty_cache()
        volume.commit()
        print(json.dumps(dict(done=name, seconds=round(time.time()-start))), flush=True)


@app.function(image=image, volumes={'/vol': volume}, secrets=[secret], gpu='H100', cpu=8, memory=98304, timeout=3600)
def fake_quant(configs: str = 'w8,a8,w8a8', windows: int = 8):
    """E5-05b attribution in fp32: symmetric int8 fake quantisation of every Linear's
    weights (per output row) and/or inputs (per token, absmax/127), the row formats
    the CQIS model uses. A simulation that splits the gap, not CQIS evidence."""
    _paths()
    import torch
    from transformers import AutoTokenizer
    import fidelity as fid
    tokenizer = AutoTokenizer.from_pretrained(SOURCE)
    backend = fid.Fp32(SOURCE)
    linears = [m for m in backend.model.modules() if isinstance(m, torch.nn.Linear)]
    original = {m: m.weight.data.cpu() for m in linears}  # host copy: two fp32 8Bs exceed 80 GB

    def q8(x, dim, group=0):
        if group:  # one scale per `group` consecutive input features
            return q8(x.unflatten(-1, (-1, group)), -1).flatten(-2)
        s = x.abs().amax(dim=dim, keepdim=True).clamp_min(1e-30)/127
        return torch.round(x/s).clamp(-127, 127)*s

    for config in configs.split(','):
        hooks = []
        for m in linears:
            w = original[m].to(m.weight.device)
            m.weight.data = q8(w, 1) if 'w8' in config else w
            if 'a8' in config:
                group = int(config.split('g')[1]) if 'g' in config else 0  # e.g. a8g128
                hooks.append(m.register_forward_pre_hook(lambda _, a, g=group: (q8(a[0], -1, g),)))
        fid.run(backend, 'cqis', tokenizer, RESULTS/'fakequant'/config/'items', ['wikitext'], {'wikitext': windows},
                checkpoint=volume.commit)
        for h in hooks:
            h.remove()
        volume.commit()
        print(json.dumps(dict(done=config)), flush=True)


if __name__ == '__main__':  # plain host: python modal_e505.py <function> [--name value ...]
    import inspect
    import sys
    fn, args = globals()[sys.argv[1]], sys.argv[2:]
    params = inspect.signature(fn).parameters
    kwargs = {k[2:]: params[k[2:]].annotation(v) for k, v in zip(args[::2], args[1::2])}
    fn(**kwargs)
