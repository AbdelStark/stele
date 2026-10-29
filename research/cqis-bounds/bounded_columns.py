"""Q26 / Draft RFC-0004 A3/A6: at-most-arity limb columns with an implicit zero tail.

Spec.count is a static capacity here, unlike the exact arity in limbs.py.
Separately expected source vectors determine live arity; bounds never use values.
"""
import limbs


def inputs(s,left,right):
    if type(left) is not tuple or type(right) is not tuple or not 1<=len(left)==len(right)<=s.count:
        raise ValueError('InputRange')
    for row,limit in ((left,s.left_max),(right,s.right_max)):
        if any(type(v) is not int or not 0<=v<=limit for v in row): raise ValueError('InputRange')


def witness(s,left,right):
    c=limbs.derive(s); inputs(s,left,right); radix=1<<s.radix_bits
    a=tuple(limbs.digits(v,s.radix_bits,len(c['left_caps'])) for v in left)
    b=tuple(limbs.digits(v,s.radix_bits,len(c['right_caps'])) for v in right)
    result=[]; carry=[0]
    for k in range(len(c['result_caps'])):
        coefficient=sum(x*br[k-i] for ar,br in zip(a,b) for i,x in enumerate(ar) if 0<=k-i<len(br))
        q,r=divmod(coefficient+carry[-1],radix); result.append(r); carry.append(q)
    return dict(left=a,right=b,result=tuple(result),carry=tuple(carry))


def check_relations(s,record,left,right,w):
    c=limbs.validate(s,record); inputs(s,left,right)
    if type(w) is not dict or set(w)!={'left','right','result','carry'}: raise ValueError('Witness')
    for side,row in (('left',left),('right',right)):
        values=w[side]
        if (type(values) is not tuple or len(values)!=len(row) or
                any(type(ds) is not tuple or any(type(v) is not int for v in ds) for ds in values)): raise ValueError('Witness')
        expected=tuple(limbs.digits(v,s.radix_bits,len(c[side+'_caps'])) for v in row)
        if values!=expected: raise ValueError('SourceDigits')
    for key,caps in (('result',c['result_caps']),('carry',c['carry_caps'])):
        if type(w[key]) is not tuple or len(w[key])!=len(caps) or any(type(v) is not int for v in w[key]): raise ValueError('Witness')
    if w['carry'][0] or w['carry'][-1]: raise ValueError('Boundary')
    for key,caps in (('result',c['result_caps']),('carry',c['carry_caps'])):
        if any(not 0<=v<=cap for v,cap in zip(w[key],caps)): raise ValueError('Range')
    for k,v in enumerate(w['result']):
        coefficient=sum(x*br[k-i] for ar,br in zip(w['left'],w['right']) for i,x in enumerate(ar) if 0<=k-i<len(br))
        if (coefficient+w['carry'][k]-v-(1<<s.radix_bits)*w['carry'][k+1])%limbs.P: raise ValueError('Relation')
    return sum(v<<(s.radix_bits*i) for i,v in enumerate(w['result']))
