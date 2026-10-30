"""Q26/Q31 actual MD sources: RFC-0022 §2.3, Draft RFC-0004 A3.

O(B) affine/byte views plus complete mantissa-range and limb-product consumers.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import limb_product as lp
import function_identity as fn

need=r.need
PREFIX=b'stele/research/q26/norm-mantissa-product/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    mantissa: int
    divisor: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=norm.constants(p.schema); base=(1<<63)+(1<<18)*p.identity; ids=(p.mantissa,p.divisor,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in ids) and len(set(ids))==3,'Spec')
    mantissa=r.Spec(4096*p.identity+1,base+1,(49151,),p.repetitions); r.derive(mantissa,d); need(2*65535<r.sc.P,'FieldBound')
    product=lp.Spec(norm.column_specs(p.schema)['normal_product'],64*p.identity+1,base+2,p.output,p.repetitions); layout=lp.derive(product,d)
    s=p.schema; function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQ',1,d,p.repetitions,p.identity,*ids)+fn.encode(function)
    return dict(mantissa=mantissa,product=product,layout=layout,cert=cert,base=base,raw=raw)


def mantissa_value(words):
    r.vector(words,2)
    value=16384+words[0]+256*words[1]
    r.vector([value],1)  # Canonical one-field representation before root encoding.
    return value


def divisor_source(v,digits):
    r.vector(digits,v['layout']['layout']['cells']); right=digits[1::2]; need(not any(right[16:]),'SourcePadding')
    return right[:16]+[0]*max(0,16-len(right))


def source(v,digits,m):
    r.vector(digits,v['layout']['layout']['cells'])
    return [x for j,right in enumerate(digits[1::2]) for x in (m>>(8*j)&255,right)]


def witness(p,m,divisor):
    v=derive(p,4); need(type(m) is int and 16384<=m<=65535,'Mantissa')
    need(type(divisor) is int and 0<=divisor<=v['cert']['D_max'],'Divisor')
    return lp.limbs.witness(v['product'].schema,(m,),(divisor,))


def expected_roots(p,m,divisor,product):
    v=derive(p,4); witness(p,m,divisor); need(type(product) is int and 0<=product<=v['cert']['MD_max'],'Product')
    return [r.root(p.mantissa,[m]),r.root(p.divisor,lp.limbs.digits(divisor,8,16)),r.root(p.output,lp.limbs.digits(product,8,v['layout']['s']))]


def transcript(v,roots,states,d):
    need(type(roots) is list and len(roots)==5 and type(states) is list and len(states)==2 and
         all(type(x) is bytes and len(x)==32 for x in roots+states),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots+states),d)


def prepare(p,m,divisor,d):
    v=derive(p,d); w=witness(p,m,divisor)
    return dict(mantissa=r.prove(v['mantissa'],[m-16384],d),product=lp.prove(v['product'],w,d))


def assemble(p,pairs,d):
    """Arithmetic producer for supplied children; only verify confers acceptance."""
    v=derive(p,d); proof={name:pairs[name][0] for name in ('mantissa','product')}; words=proof['mantissa']['words']; digits=proof['product']['input']['digits']
    roots=[r.root(p.mantissa,[mantissa_value(words)]),r.root(p.divisor,divisor_source(v,digits)),
           lp.cr.source_root(v['layout']['output'],proof['product']['output']['words']),r.source_root(v['mantissa'],words),lp.ls.source_root(v['layout']['input'],digits)]
    return proof,transcript(v,roots,[pairs[name][1] for name in ('mantissa','product')],d).state


def prove(p,m,divisor,d):
    return assemble(p,prepare(p,m,divisor,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d)
    need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'mantissa','product'},'ProofShape')
    try:
        part=proof['mantissa']; need(type(part) is dict and 'words' in part,'ProofShape'); words=part['words']
        offset_root=r.source_root(v['mantissa'],words); mantissa=r.verify(v['mantissa'],offset_root,part,d)
        m=mantissa_value(words); need(r.root(p.mantissa,[m])==expected[0],'CommitmentMismatch')
    except ValueError as error: raise ValueError('Mantissa:'+str(error)) from None
    try:
        part=proof['product']; need(type(part) is dict and type(part.get('input')) is dict and 'digits' in part['input'],'ProofShape')
        digits=part['input']['digits']; divisor=divisor_source(v,digits)
    except ValueError as error: raise ValueError('Product:'+str(error)) from None
    need(r.root(p.divisor,divisor)==expected[1],'Divisor:CommitmentMismatch')
    try:
        need(digits==source(v,digits,m),'SourceJoin'); source_root=lp.ls.source_root(v['layout']['input'],digits)
        product=lp.verify(v['product'],[source_root,expected[2]],part,d)
    except ValueError as error: raise ValueError('Product:'+str(error)) from None
    t=transcript(v,expected+[offset_root,source_root],[mantissa['state'],product['state']],d); a,b=mantissa['account'],product['account']
    return dict(state=t.state,mantissa=mantissa,product=product,draws=dict(t.draws),
        account=dict(identities=[(a['identity_numerator'],a['identity_power'])]+b['identities'],lookup_reduction_numerator=a['lookup_reduction_numerator']+b['lookup_reduction_numerator'],
            range_reduction_numerator=a['range_reduction_numerator']+b['range_reduction_numerator'],
            product_identity_numerator=b['product_identity_numerator'],product_reduction_numerator=b['product_reduction_numerator'],denominator=r.sc.P**d))
