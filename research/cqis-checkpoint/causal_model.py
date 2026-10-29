"""Q26 / Draft RFC-0004 A9: complete causal numerical evaluation, not a proof."""
from dataclasses import dataclass
import decoder_block as b
from alignment import round_i16
from quantiser import require


@dataclass(frozen=True)
class Model:
    embedding: b.Matrix
    head: b.Matrix | None  # None uses the exact same vocabulary-major embedding.
    blocks: tuple
    final_norm: b.norm.Parameters
    gains: tuple
    policy: tuple
    logits_fraction: int

    def __post_init__(self):
        require(type(self.embedding) is b.Matrix and (self.head is None or type(self.head) is b.Matrix),'Weights')
        require(type(self.blocks) is tuple and 1<=len(self.blocks)<=128 and
                all(type(p) is b.Params for p in self.blocks),'Blocks')
        d = len(self.embedding.codes[0]); vocab = len(self.embedding.codes)
        require(all(p.norm1.d==d for p in self.blocks),'Shape')
        require(self.head is None or (len(self.head.codes),len(self.head.codes[0]))==(vocab,d),'Shape')
        require(type(self.final_norm) is b.norm.Parameters and self.final_norm.d==d,'Shape')
        require(all(left.fout==right.norm1.F for left,right in zip(self.blocks,self.blocks[1:])) and
                self.blocks[-1].fout==self.final_norm.F,'Units')
        require(type(self.gains) is tuple,'Shape'); b.pa.wide_row(list(self.gains),d)
        require(type(self.policy) is tuple and len(self.policy)==2,'Policy'); b.pa.a.policy(*self.policy)
        b.pa.a.integer(self.logits_fraction,0,30,'Units')
        length = len(self.blocks[0].attention.rotations)
        require(all(len(p.attention.rotations)==length for p in self.blocks),'Length')
        matrices = [self.embedding]+([] if self.head is None else [self.head])+[w for p in self.blocks for w in p.weights]
        require(sum(len(w.codes)*len(w.codes[0]) for w in matrices)<=1 << 22,'Capacity')


def tokens(p, values):
    require(type(p) is Model,'Model')
    require(type(values) is list and 1<=len(values)<=len(p.blocks[0].attention.rotations),'Length')
    require(all(type(t) is int and 0<=t<len(p.embedding.codes) for t in values),'Token')
    cells = len(p.embedding.codes)+8*p.final_norm.d*(len(p.blocks)+1)
    cells += 4*sum(q.attention.groups*q.attention.width for q in p.blocks)
    require(len(values)*cells<=1 << 22,'Capacity')


def embed(p, token):
    w = p.embedding
    return [round_i16(x*w.mantissas[token],-w.exponent-p.blocks[0].norm1.F) for x in w.codes[token]]


def finish(p, row):
    wide = b.norm.evaluate(p.final_norm,row,list(p.gains))['output']
    x = b.quantize(wide,p.final_norm.E,p.policy)
    logits = b.linear(p.embedding if p.head is None else p.head,x,p.logits_fraction)
    return dict(normalized=wide,input=x,logits=logits)


@dataclass(frozen=True)
class Cached:
    scope: Model
    tokens: tuple
    layers: tuple


def full(p, sequence):
    tokens(p,sequence); rows = [embed(p,t) for t in sequence]; cuts = [rows]; caches = []
    for block in p.blocks:
        result = b.full(block,rows,list(range(len(sequence))))
        rows = [r['output'] for r in result['rows']]; cuts.append(rows); caches.append(result['cache'])
    heads = [finish(p,row) for row in rows]
    return dict(cuts=cuts,heads=heads,cache=Cached(p,tuple(sequence),tuple(caches)))


def step(p, token, cache=None):
    require(type(p) is Model,'Model')
    sequence = []
    if cache is not None:
        require(type(cache) is Cached and type(cache.scope) is Model and cache.scope==p,'CacheScope')
        require(type(cache.tokens) is tuple and type(cache.layers) is tuple and len(cache.layers)==len(p.blocks),'Cache')
        sequence = list(cache.tokens); tokens(p,sequence)
        require(all(type(c) is b.Cached and c.scope==block and type(c.attention) is b.pa.Cached and
                    c.attention.positions==tuple(range(len(sequence))) for c,block in zip(cache.layers,p.blocks)),'Cache')
    sequence.append(token); tokens(p,sequence); position = len(sequence)-1
    row = embed(p,token); cuts = [row]; caches = []
    for j,block in enumerate(p.blocks):
        result,new = b.step(block,row,position,None if cache is None else cache.layers[j])
        row = result['output']; cuts.append(row); caches.append(new)
    head = finish(p,row)  # No caller-visible state change until every layer and the head succeeds.
    return dict(cuts=cuts,head=head),Cached(p,tuple(sequence),tuple(caches))


def choose(logits):
    require(type(logits) is list and 1<=len(logits)<=1 << 20 and
            all(type(x) is int and -32768<=x<=32767 for x in logits),'Logits')
    return max(range(len(logits)),key=lambda j:logits[j])  # Iteration order gives the lowest tie.


def generate(p, prompt, maximum_new, eos):
    tokens(p,prompt)
    b.pa.a.integer(maximum_new,0,len(p.blocks[0].attention.rotations)-len(prompt),'Length')
    b.pa.a.integer(eos,0,len(p.embedding.codes)-1,'Token')
    result = full(p,prompt); cache = result['cache']; logits = result['heads'][-1]['logits']
    sequence = list(prompt); stop = 'limit'
    for _ in range(maximum_new):
        selected = choose(logits)
        row,cache = step(p,selected,cache); sequence.append(selected); logits = row['head']['logits']
        if selected==eos: stop='eos'; break
    return dict(tokens=sequence,stop=stop,cache=cache)


def check_generation(p, prompt, maximum_new, eos, sequence, stop):
    """Full numerical replay only: no succinct verifier, commitment or ZK claim."""
    tokens(p,sequence)
    require(type(stop) is str and stop in ('limit','eos'),'Generation')
    actual = generate(p,prompt,maximum_new,eos)
    require((sequence,stop)==(actual['tokens'],actual['stop']),'Generation')
