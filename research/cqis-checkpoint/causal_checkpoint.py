"""Pinned Q26 checkpoint fixture; explicit choices, not a general HF lowerer."""
from fractions import Fraction as Q
import hashlib
import json
from pathlib import Path
import struct
import causal_model as m
import model_config as c
import model_scaled_bounds
import model_row_bounds
import model_rotary_bounds
import model_residual_bounds
import model_greedy_bounds
import source
import rope

REPOSITORY = 'trl-internal-testing/tiny-random-LlamaForCausalLM'
REVISION = '2c542e4731d42d3bb68324c4eca16df9f93b8b33'
CONFIG = '3305bd985f960e7d680f4710ffd2830a55a5f149e8d8d2d18ff0b3fc508cc97f'
WEIGHTS = 'aaa2c22c920d4e9c0943dc1f9d73fd4c687c2aa9c1ebcb878281c234075cec50'


def prepare(config_bytes, raw):
    m.require(hashlib.sha256(config_bytes).hexdigest()==CONFIG,'ConfigDigest')
    config = json.loads(config_bytes,parse_float=Q,parse_constant=source.no_number,object_pairs_hook=source.unique)
    d,h,layers,vocab,ff = [config[key] for key in ('hidden_size','num_attention_heads','num_hidden_layers','vocab_size','intermediate_size')]
    specs = [m.b.records.Spec(name,'binary32',shape,8 if len(shape)==2 else 16,0 if len(shape)==2 else 14)
             for name,shape in [('model.embed_tokens.weight',(vocab,d)),('lm_head.weight',(vocab,d)),('model.norm.weight',(d,))]]
    roles = ['self_attn.'+name+'_proj.weight' for name in ('q','k','v','o')]+['mlp.'+name+'_proj.weight' for name in ('up','gate','down')]
    shapes = [(d,d)]*4+[(ff,d),(ff,d),(d,ff)]
    ignored = []
    for i in range(layers):
        prefix = 'model.layers.'+str(i)+'.'
        specs.extend(m.b.records.Spec(prefix+name,'binary32',shape,8,0) for name,shape in zip(roles,shapes))
        specs.extend(m.b.records.Spec(prefix+name,'binary32',(d,),16,14)
                     for name in ('input_layernorm.weight','post_attention_layernorm.weight'))
        ignored.append(prefix+'self_attn.rotary_emb.inv_freq')
    prepared = source.prepare(specs,ignored,raw,bytes.fromhex(WEIGHTS))
    by_name = {s.name:s for s in specs}
    # Explicit CQIS choices: split/base RoPE, 2048 positions, theta=10000; no float buffer reuse.
    rp = rope.Parameters(d//h,2048,Q(10000),layout='split')
    att = m.b.pa.a.Config(m.b.pa.a.fn.Function('exp_q/nearest',1,bytes([15,7,12])),12,12,'dynamic',0,'dynamic',0,'exact',0)
    ap = c.Projection(h,h,d//h,12,12,'dynamic',0,'dynamic',0,1,-1,att,c.fn.Representation(att.function,0,b''),rp)
    epsilon = config['rms_norm_eps']; norm = m.b.norm.Parameters(d,12,14,12,epsilon.numerator,epsilon.denominator)
    blocks = []
    for i in range(layers):
        prefix = 'model.layers.'+str(i)+'.'
        blocks.append(c.Block(norm,norm,by_name[prefix+'input_layernorm.weight'],by_name[prefix+'post_attention_layernorm.weight'],
                      tuple(by_name[prefix+name] for name in roles),ap,m.b.pa.a.fn.Function('silu_q',1,bytes([12,12])),
                      12,12,12,12,('dynamic',0),('dynamic',0),('dynamic',0)))
    configuration = c.Config(2048,by_name['model.embed_tokens.weight'],by_name['lm_head.weight'],tuple(blocks),norm,
                             by_name['model.norm.weight'],('dynamic',0),12)
    config_bytes = c.encode(configuration); config_id = c.identity(configuration)
    model = c.load(config_id,config_bytes,prepared['digest_cqis'],prepared['artifact'])
    info = dict(repository=REPOSITORY,revision=REVISION,config_sha256=CONFIG,source_sha256=WEIGHTS,
                selected_tensors=len(specs),ignored_tensors=ignored,parameters=sum(m.b.records.count(s) for s in specs),
                artifact_bytes=len(prepared['artifact']),quantiser_id=prepared['quantiser_id'].hex(),
                model_config_bytes=len(config_bytes),model_config_id=config_id.hex(),
                model_instance_id=c.instance_identity(config_id,prepared['digest_cqis']).hex(),
                source_preparation_id=prepared['source_preparation_id'].hex(),digest_cqis=prepared['digest_cqis'].hex(),
                choices=dict(weight_bits=8,wide_fraction=12,gain_fraction=14,epsilon=[1,1000000],
                             exp=[15,7,12],score=[1,-1],rope=[4,2048,10000,'split'],
                             row_mode='dynamic',accumulation='exact',tied=False))
    return model,info


def check_checkpoint(prefix, reference, *, write=False):
    config = Path(prefix+'-config.json').read_bytes(); raw = Path(prefix+'-model.safetensors').read_bytes()
    from check_attention import reject
    reject('ConfigDigest',lambda: prepare(config+b' ',raw))
    reject('SourceDigest',lambda: prepare(config,raw[:-1]+bytes([raw[-1]^1])))
    model,info = prepare(config,raw); sequence = [0,42,1337,31999]
    info.update(model_scaled_bounds.evidence(model))
    info.update(model_row_bounds.evidence(model))
    info.update(model_rotary_bounds.evidence(model))
    info.update(model_residual_bounds.evidence(model))
    info.update(model_greedy_bounds.evidence(model))
    actual = m.full(model,sequence); expected = reference(model,sequence)
    assert {k:actual[k] for k in expected}==expected
    cache = None
    for j,t in enumerate(sequence):
        row,cache = m.step(model,t,cache)
        assert row==dict(cuts=[c[j] for c in actual['cuts']],head=actual['heads'][j])
    assert cache==actual['cache']
    generated = m.generate(model,sequence,2,1)
    replay = reference(model,generated['tokens'])
    assert generated['cache']==m.full(model,generated['tokens'])['cache']
    for i,t in enumerate(generated['tokens'][len(sequence):],len(sequence)):
        logits = replay['heads'][i-1]['logits']; maximum = max(logits)
        assert t==next(j for j,v in enumerate(logits) if v==maximum)
    greedy_rows=tuple(tuple(replay['heads'][i-1]['logits']) for i in range(len(sequence),len(generated['tokens'])))
    assert model_greedy_bounds.check_generation(model,tuple(sequence),2,1,tuple(generated['tokens']),
                                               generated['stop'],greedy_rows)==tuple(generated['tokens'])
    info.update(prompt=sequence,generated=generated['tokens'][len(sequence):],stop=generated['stop'],
                logits_sha256=hashlib.sha256(b''.join(struct.pack('<h',v) for r in actual['heads'] for v in r['logits'])).hexdigest())
    path = Path(__file__).with_name('causal-checkpoint.json')
    if write:
        with path.open('x') as out: json.dump(info,out,indent=2,sort_keys=True); out.write('\n')
    assert info==json.loads(path.read_text())
    return info
