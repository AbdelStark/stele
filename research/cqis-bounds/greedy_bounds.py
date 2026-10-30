"""Q26 / RFC-0004 §7, Draft A3/A9: static first-maximum and public stopping checks."""
from dataclasses import asdict, dataclass
from requant import same
from encoding import unsigned

P=2**31-1
TAG=b'stele/research/q26/greedy-bounds/v1\0'
SCALARS=('logit_max','logit_high','selected_max','position_max','difference_max','gap_max',
         'prefix_bit_max','strict_rhs_max','entry_capacity')


@dataclass(frozen=True)
class Spec:
    vocabulary: int
    fraction: int
    length: int


def derive(p):
    if (type(p) is not Spec or any(type(v) is not int for v in asdict(p).values()) or
            not 1<=p.vocabulary<=1<<20 or not 0<=p.fraction<=30 or not 1<=p.length<=1<<20): raise ValueError('Spec')
    c=dict(asdict(p),prime=P,logit_max=32768,logit_high=32767,selected_max=p.vocabulary-1,
           position_max=p.length-1,difference_max=65535,gap_max=65535,prefix_bit_max=1,
           strict_rhs_max=65536,entry_capacity=1<<22)
    if any(2*c[k]>=P for k in ('logit_max','difference_max','strict_rhs_max')): raise ValueError('FieldBound')
    return c


def validate(p,record):
    expected=derive(p)
    if not same(record,expected): raise ValueError('Certificate')
    return expected


def inputs(p,position,xs):
    derive(p)
    if type(position) is not int or not 0<=position<p.length: raise ValueError('Position')
    if (type(xs) is not tuple or len(xs)!=p.vocabulary or
            any(type(x) is not int or not -32768<=x<=32767 for x in xs)): raise ValueError('Input')


def witness(p,position,xs):
    inputs(p,position,xs)
    selected=max(range(p.vocabulary),key=lambda i:xs[i]); maximum=xs[selected]
    entries=tuple(dict(difference=maximum-x,gap=maximum-x-int(i<selected)) for i,x in enumerate(xs))
    return dict(position=position,selected=selected,maximum=maximum,entries=entries)


def check_relations(p,record,position,selected,xs,w):
    """Selected token, position and logits are separately expected; source authentication is external."""
    c=validate(p,record); inputs(p,position,xs)
    if type(selected) is not int or not 0<=selected<p.vocabulary: raise ValueError('Token')
    if (type(w) is not dict or set(w)!={'position','selected','maximum','entries'} or
            type(w['entries']) is not tuple or len(w['entries'])!=p.vocabulary): raise ValueError('Witness')
    if type(w['position']) is not int or w['position']!=position: raise ValueError('Position')
    if type(w['selected']) is not int or w['selected']!=selected: raise ValueError('Selected')
    if type(w['maximum']) is not int or not -32768<=w['maximum']<=32767: raise ValueError('Range')
    if (w['maximum']-xs[selected])%P: raise ValueError('Attainment')
    for i,(x,e) in enumerate(zip(xs,w['entries'])):
        if type(e) is not dict or set(e)!={'difference','gap'} or any(type(v) is not int for v in e.values()):
            raise ValueError('Witness')
        if not 0<=e['difference']<=c['difference_max'] or not 0<=e['gap']<=c['gap_max']: raise ValueError('Range')
        if (e['difference']-(w['maximum']-x))%P: raise ValueError('Difference')
        # Public index/selected-token comparison fixes the prefix bit; it is not a free witness.
        if (e['difference']-e['gap']-int(i<selected))%P: raise ValueError('FirstMaximum')
    return selected


def check_generation(p,record,prompt,maximum_new,eos,sequence,stop,rows,witnesses):
    """Public boundary plus plaintext row checks; does not prove model/logit-row ownership."""
    c=validate(p,record)
    if type(prompt) is not tuple or not 1<=len(prompt)<=p.length: raise ValueError('Length')
    if type(maximum_new) is not int or not 0<=maximum_new<=p.length-len(prompt): raise ValueError('Length')
    if type(eos) is not int or not 0<=eos<p.vocabulary: raise ValueError('Token')
    if type(sequence) is not tuple or not len(prompt)<=len(sequence)<=len(prompt)+maximum_new: raise ValueError('Length')
    if any(type(t) is not int or not 0<=t<p.vocabulary for t in prompt+sequence): raise ValueError('Token')
    if sequence[:len(prompt)]!=prompt: raise ValueError('Prefix')
    generated=sequence[len(prompt):]; count=len(generated)
    if type(stop) is not str or stop not in ('limit','eos'): raise ValueError('Stop')
    if eos in generated[:-1]: raise ValueError('Stop')
    if generated and generated[-1]==eos:
        if stop!='eos': raise ValueError('Stop')
    elif stop!='limit' or count!=maximum_new: raise ValueError('Stop')
    if (type(rows) is not tuple or type(witnesses) is not tuple or len(rows)!=count or
            len(witnesses)!=count or count*p.vocabulary>c['entry_capacity']): raise ValueError('Rows')
    for i,(selected,xs,w) in enumerate(zip(generated,rows,witnesses)):
        check_relations(p,record,len(prompt)-1+i,selected,xs,w)
    return sequence


def encode(p):
    c=derive(p)
    raw=TAG+unsigned(p.vocabulary,4)+bytes([p.fraction])+unsigned(p.length,4)
    raw+=unsigned(P,4)+bytes([len(SCALARS)])+b''.join(unsigned(c[k],4) for k in SCALARS)
    if len(raw)>128: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>128 or raw!=expected: raise ValueError('Encoding')
