# /// script
# requires-python = ">=3.12"
# dependencies = ["numpy==2.3.4", "blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Q26 complete-model arithmetic, full/cache and greedy replay checks."""
from dataclasses import asdict, replace
from fractions import Fraction as Q
import hashlib
import json
import random
import sys
import causal_model as m
from check_decoder_block import configuration, reference as block_reference, norm, quantized, linear
from check_attention import rounded, reject


def reference(p, tokens):
    w = p.embedding; fraction = p.blocks[0].norm1.F
    rows = [[rounded(Q(v*w.mantissas[t])*Q(2)**(w.exponent+fraction)) for v in w.codes[t]] for t in tokens]
    if any(not -32768<=v<=32767 for row in rows for v in row): raise ValueError('Overflow')
    cuts = [rows]
    for block in p.blocks:
        rows = [r['output'] for r in block_reference(block,rows,list(range(len(tokens))))]; cuts.append(rows)
    heads = []
    for row in rows:
        wide = norm(p.final_norm,row,p.gains)
        inputs = quantized(wide,p.final_norm.E,p.policy)
        heads.append(dict(normalized=wide,input=inputs,logits=linear(p.embedding if p.head is None else p.head,inputs,p.logits_fraction)))
    return dict(cuts=cuts,heads=heads)


def make(rng, case):
    blocks = tuple(configuration(rng,case+2*j,length=8) for j in range(1+case%3))
    dim = blocks[0].norm1.d; vocabulary = 3+case%9
    def weight():
        return m.b.Matrix(4 if case%2 else 8,-14,tuple(rng.randrange(512,2049) for _ in range(vocabulary)),
                          tuple(tuple(rng.randrange(-7,8) for _ in range(dim)) for _ in range(vocabulary)))
    final = m.b.norm.Parameters(dim,blocks[-1].fout,8,8,1,100000)
    return m.Model(weight(),None if case%2 else weight(),blocks,final,(256,)*dim,
                   ('dynamic',0),20 if case%17==0 else 6+case%7)


def check():
    rng = random.Random(2631); digest = hashlib.sha256(); accepted = rejected = greedy_cases = 0
    for case in range(10000):
        p = make(rng,case); tokens = [rng.randrange(len(p.embedding.codes)) for _ in range(1+case%3)]
        try: expected = reference(p,tokens)
        except ValueError as error:
            reject(str(error),lambda: m.full(p,tokens)); rejected += 1; digest.update(b'reject'); continue
        actual = m.full(p,tokens)
        assert {k:actual[k] for k in expected}==expected
        cache = None
        for j,t in enumerate(tokens):
            row,cache = m.step(p,t,cache)
            assert row==dict(cuts=[cut[j] for cut in expected['cuts']],head=expected['heads'][j])
        assert cache==actual['cache']; accepted += 1
        data=dict(cuts=expected['cuts'],heads=[dict(h,input=asdict(h['input'])) for h in expected['heads']])
        digest.update(json.dumps(data,sort_keys=True,separators=(',',':')).encode())
        if case%100==1:
            sequence = list(tokens); stop = 'limit'; eos = 1
            for _ in range(2):
                logits = reference(p,sequence)['heads'][-1]['logits']
                chosen = sorted(range(len(logits)),key=lambda i:(-logits[i],i))[0]
                sequence.append(chosen)
                if chosen==eos: stop='eos'; break
            generated = m.generate(p,tokens,2,eos)
            assert generated['tokens']==sequence and generated['stop']==stop
            assert generated['cache']==m.full(p,sequence)['cache']
            m.check_generation(p,tokens,2,eos,sequence,stop)
            bad = sequence.copy(); bad[-1]=(bad[-1]+1)%len(p.embedding.codes)
            reject('Generation',lambda: m.check_generation(p,tokens,2,eos,bad,stop)); greedy_cases += 1
    p = make(rng,1); vocabulary = len(p.embedding.codes); dim = p.final_norm.d
    # Zero logits force the lowest token; EOS is included and fully evaluated.
    zero = m.b.Matrix(8,0,(1,)*vocabulary,((0,)*dim,)*vocabulary)
    tied = replace(p,embedding=zero,head=None)
    assert m.generate(tied,[2],5,0)['tokens']==[2,0]
    assert m.generate(tied,[0],0,0)['stop']=='limit'
    assert m.generate(tied,[0],2,1)['tokens']==[0,0,0]
    reject('Generation',lambda: m.check_generation(tied,[2],5,0,[2,0,0],'eos'))
    reject('Generation',lambda: m.check_generation(tied,[2],5,0,[2,1],'eos'))
    reject('Generation',lambda: m.check_generation(tied,[2],5,0,[2,0],'limit'))
    assert m.choose([-32768,32767,32767])==1
    reject('Token',lambda: m.full(p,[True])); reject('Token',lambda: m.full(p,[vocabulary]))
    reject('Length',lambda: m.full(p,[])); reject('Length',lambda: m.generate(p,[0],8,1))
    reject('Length',lambda: m.generate(p,[0],True,1))
    reject('Units',lambda: replace(p,final_norm=replace(p.final_norm,F=9)))
    reject('Units',lambda: replace(p,blocks=(replace(p.blocks[0],fout=9),)+p.blocks[1:]))
    reject('Shape',lambda: replace(p,head=replace(zero,codes=zero.codes[:-1],mantissas=zero.mantissas[:-1])))
    _,cache = m.step(p,0)
    blocks = tuple(replace(q,norm1=replace(q.norm1,F=6+j),norm2=replace(q.norm2,F=10-j),fout=7+j)
                   for j,q in enumerate(p.blocks))
    mixed = replace(p,blocks=blocks,final_norm=replace(p.final_norm,F=6+len(blocks)))
    expected = reference(mixed,[0,1,2]); actual = m.full(mixed,[0,1,2])
    assert {k:actual[k] for k in expected}==expected
    state = None
    for j,t in enumerate([0,1,2]):
        row,state = m.step(mixed,t,state); assert row['head']==expected['heads'][j]
    assert state==actual['cache']
    reject('CacheScope',lambda: m.step(replace(p,logits_fraction=p.logits_fraction+1),1,cache))
    reject('Cache',lambda: m.step(p,1,replace(cache,layers=cache.layers[:-1])))
    reject('Cache',lambda: m.step(p,1,replace(cache,tokens=cache.tokens+(1,))))
    # Failure occurs after every layer has produced a candidate cache, at the final head.
    failing = replace(p,embedding=replace(zero,codes=((0,)*dim,(1,)*dim)+zero.codes[2:]),
                      head=m.b.Matrix(8,1024,(65535,)*vocabulary,((127,)*dim,)*vocabulary))
    _,stable = m.step(failing,0)
    reject('Overflow',lambda: m.step(failing,1,stable))
    assert stable.tokens==(0,)
    row,following = m.step(failing,0,stable); assert following.tokens==(0,0) and row['head']['logits']==[0]*vocabulary
    assert (accepted,rejected,greedy_cases)==(9412,588,94)
    assert digest.hexdigest()=='9ecded18e4cd7a628de43625a31223356e594c67291c5ab2f6aa57e5e05dc4eb'
    print(json.dumps(dict(seed=2631,accepted=accepted,rejected=rejected,greedy_cases=greedy_cases,
                          sha256=digest.hexdigest()),sort_keys=True))


if __name__ == '__main__':
    if sys.argv[1:] in (['--rotary-bounds'],['--rotary-controls']):
        from check_rotary_bounds import check, controls
        check() if sys.argv[1]=='--rotary-bounds' else controls()
    elif sys.argv[1:] in (['--row-bounds'],['--row-controls'],['--row-models']):
        from check_row_bounds import check, controls, models
        {'--row-bounds':check,'--row-controls':controls,'--row-models':models}[sys.argv[1]]()
    elif sys.argv[1:] in (['--scaled-bounds'],['--scaled-controls']):
        from check_scaled_bounds import check, controls
        check() if sys.argv[1]=='--scaled-bounds' else controls()
    elif sys.argv[1:] in (['--configuration'],['--configuration-controls']):
        from check_model_config import check, controls
        if sys.argv[1]=='--configuration': check()
        controls()
    elif len(sys.argv) in (3,4) and sys.argv[1]=='--checkpoint':
        from causal_checkpoint import check_checkpoint
        assert len(sys.argv)==3 or sys.argv[3]=='--write'
        print(json.dumps(check_checkpoint(sys.argv[2],reference,write=len(sys.argv)==4),sort_keys=True))
    else:
        assert len(sys.argv)==1
        check()
