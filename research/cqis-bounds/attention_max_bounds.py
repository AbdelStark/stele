"""Q26 / RFC-0009 A1, Draft RFC-0004 A3/A6: masked attained maximum, no proof consumer."""
from dataclasses import asdict, dataclass
import limbs
from requant import same, equal_digits
from encoding import unsigned

P=limbs.P
TAG=b'stele/research/q26/attention-max-bounds/v1\0'
SCALARS=('position_max','score_offset_max','domain_max','delta_max','gap_max','prefix_max','entry_capacity')


@dataclass(frozen=True)
class Spec:
    length: int
    score_max: int
    domain_bits: int
    fraction: int


def constants(p):
    if (type(p) is not Spec or any(type(v) is not int for v in asdict(p).values()) or not 1<=p.length<=1<<20 or
            not 0<=p.score_max<1<<31 or not 7<=p.domain_bits<=31 or not 0<=p.fraction<=30): raise ValueError('Spec')
    offset=2*p.score_max; domain=1<<p.domain_bits; delta=min(offset,domain)
    return dict(asdict(p),prime=P,position_max=p.length-1,score_offset_max=offset,domain_max=domain,
                delta_max=delta,gap_max=delta,prefix_max=1,entry_capacity=1<<20)


def column_specs(p):
    c=constants(p)
    return dict(shared_columns=dict(maximum=limbs.Spec(1,c['score_offset_max'],1,8)),
                entry_columns=dict(difference=limbs.Spec(2,c['score_offset_max'],1,8),
                                   first_maximum=limbs.Spec(2,max(c['delta_max'],1),1,8)))


def derive(p):
    return dict(constants(p),**{group:{name:limbs.derive(s) for name,s in specs.items()} for group,specs in column_specs(p).items()})


def validate(p,record):
    c=derive(p)
    if not same(record,c): raise ValueError('Certificate')
    return c


def inputs(p,position,ids,scores,allowed):
    constants(p)
    if type(position) is not int or not 0<=position<p.length: raise ValueError('Position')
    if (type(ids) is not tuple or not 1<=len(ids)<=p.length or any(type(j) is not int or not 0<=j<p.length for j in ids) or
            any(x>=y for x,y in zip(ids,ids[1:]))): raise ValueError('Positions')
    if type(scores) is not tuple or len(scores)!=len(ids) or any(type(v) is not int or abs(v)>p.score_max for v in scores):
        raise ValueError('Input')
    if type(allowed) is not tuple or len(allowed)!=len(ids) or any(type(b) is not bool for b in allowed): raise ValueError('Mask')
    if not any(allowed): raise ValueError('EmptyRow')


def selection(ids,allowed,selected):
    if type(selected) is not int or selected not in ids: raise ValueError('Selection')
    index=ids.index(selected)
    if not allowed[index]: raise ValueError('Selection')
    return index


def column_inputs(p,ids,scores,allowed,w):
    shared=dict(maximum=((w['maximum']+p.score_max,),(1,)))
    entries=[dict(difference=((x+p.score_max,e['delta']),(int(bit),1)),
                  first_maximum=((e['gap'],int(bit and j<w['selected'])),(1,1)))
             for j,x,bit,e in zip(ids,scores,allowed,w['entries'])]
    return shared,entries


def attach(p,ids,scores,allowed,w):
    specs=column_specs(p); shared,entries=column_inputs(p,ids,scores,allowed,w)
    w['columns']={name:limbs.witness(s,*shared[name]) for name,s in specs['shared_columns'].items()}
    for e,values in zip(w['entries'],entries):
        e['columns']={name:limbs.witness(s,*values[name]) for name,s in specs['entry_columns'].items()}
    return w


def witness(p,position,ids,scores,allowed):
    c=derive(p); inputs(p,position,ids,scores,allowed)
    index=max((i for i,b in enumerate(allowed) if b),key=lambda i:scores[i]); selected=ids[index]; maximum=scores[index]
    deltas=tuple(maximum-x if bit else 0 for x,bit in zip(scores,allowed))
    if any(d>c['delta_max'] for d in deltas): raise ValueError('Domain')
    entries=tuple(dict(delta=d,gap=d-int(bit and j<selected)) for j,bit,d in zip(ids,allowed,deltas))
    return attach(p,ids,scores,allowed,dict(position=position,positions=ids,selected=selected,maximum=maximum,entries=entries))


def check_relations(p,record,position,ids,scores,allowed,selected,w):
    """Expected ordered sources/masks and selected ID are conditional; no wide equality modulo p."""
    c=validate(p,record); inputs(p,position,ids,scores,allowed); index=selection(ids,allowed,selected); specs=column_specs(p)
    if (type(w) is not dict or set(w)!={'position','positions','selected','maximum','entries','columns'} or
            type(w['entries']) is not tuple or len(w['entries'])!=len(ids) or type(w['maximum']) is not int or
            type(w['columns']) is not dict or w['columns'].keys()!=specs['shared_columns'].keys()): raise ValueError('Witness')
    if type(w['position']) is not int or w['position']!=position: raise ValueError('Position')
    if type(w['positions']) is not tuple or any(type(j) is not int for j in w['positions']) or w['positions']!=ids: raise ValueError('Positions')
    if type(w['selected']) is not int or w['selected']!=selected: raise ValueError('Selected')
    if abs(w['maximum'])>p.score_max: raise ValueError('Range')
    for e,bit in zip(w['entries'],allowed):
        if (type(e) is not dict or set(e)!={'delta','gap','columns'} or type(e['delta']) is not int or type(e['gap']) is not int or
                type(e['columns']) is not dict or e['columns'].keys()!=specs['entry_columns'].keys()): raise ValueError('Witness')
        if not 0<=e['delta']<=c['delta_max'] or not 0<=e['gap']<=c['gap_max']: raise ValueError('Range')
        if not bit and (e['delta']!=0 or e['gap']!=0): raise ValueError('Masked')
    shared,entries=column_inputs(p,ids,scores,allowed,w)
    for name,s in specs['shared_columns'].items(): limbs.check_relations(s,c['shared_columns'][name],*shared[name],w['columns'][name])
    maximum=w['columns']['maximum']['result']
    equal_digits(maximum,limbs.digits(scores[index]+p.score_max,8,8))
    for e,bit,values in zip(w['entries'],allowed,entries):
        for name,s in specs['entry_columns'].items(): limbs.check_relations(s,c['entry_columns'][name],*values[name],e['columns'][name])
        equal_digits(e['columns']['difference']['result'],tuple(int(bit)*d for d in maximum))
        equal_digits(e['columns']['first_maximum']['result'],limbs.digits(e['delta'],8,8))
    return w['maximum'],selected,tuple(e['delta'] for e in w['entries'])


def encode(p):
    c=derive(p); raw=TAG+unsigned(p.length,4)+unsigned(p.score_max,4)+bytes([p.domain_bits,p.fraction])
    raw+=unsigned(P,4)+bytes([8,len(SCALARS)])+b''.join(c[k].to_bytes(8,'little') for k in SCALARS)
    for group in ('shared_columns','entry_columns'):
        raw+=bytes([len(c[group])])
        for i,rec in enumerate(c[group].values(),1):
            raw+=bytes([i])+unsigned(rec['count'],4)+b''.join(rec[k].to_bytes(8,'little') for k in ('left_max','right_max','result_max'))
            raw+=bytes(len(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(bytes(rec[k]) for k in ('left_caps','right_caps','result_caps'))
            raw+=b''.join(unsigned(v,4) for k in ('carry_caps','lhs','rhs') for v in rec[k])
    if len(raw)>512: raise ValueError('Capacity')
    return raw


def validate_bytes(p,raw):
    expected=encode(p)
    if type(raw) is not bytes or len(raw)>512 or raw!=expected: raise ValueError('Encoding')
