"""Q26/Q31 consumed A=MD+R: RFC-0022 §2.3, Draft RFC-0004 A3.

O(B) exact source views plus complete count2 limb-product consumers.
"""
from dataclasses import dataclass
import struct
import norm_bounds as norm
import wide_range as r
import limb_product as lp
import function_identity as fn

need=r.need
PREFIX=b'stele/research/q26/norm-sum/v1\0'


@dataclass(frozen=True)
class Spec:
    schema: norm.Spec
    identity: int
    product: int
    remainder: int
    output: int
    repetitions: int


def derive(p,d):
    need(type(p) is Spec and type(d) is int and d in (4,8),'Spec')
    need(type(p.identity) is int and 0<=p.identity<1<<44 and type(p.repetitions) is int and p.repetitions in (1,2),'Spec')
    cert=norm.constants(p.schema);base=(1<<63)+(1<<18)*p.identity;ids=(p.product,p.remainder,p.output)
    need(all(type(x) is int and 2<=x<1<<64 and not base<=x<base+(1<<18) for x in ids) and len(set(ids))==3,'Spec')
    specs=norm.column_specs(p.schema);summation=lp.Spec(specs['normal_sum'],64*p.identity+1,base+1,base+2,p.repetitions);layout=lp.derive(summation,d)
    # Match full LP output representations, including its strict next-power padding.
    slots=lambda name:1<<len(lp.limbs.derive(specs[name])['result_caps']).bit_length()
    s=p.schema;function=fn.Function('rmsnorm_q',1,struct.pack('<HBBBII',s.d,s.F,s.G,s.E,s.en,s.ed))
    raw=PREFIX+struct.pack('<BBBQQQQ',1,d,p.repetitions,p.identity,*ids)+fn.encode(function)
    return dict(sum=summation,layout=layout,cert=cert,base=base,raw=raw,md_slots=slots('normal_product'),
                a_slots=slots('scaled'),remainder_max=min(cert['MD_max'],(1<<128)-1))


def extend(values,size):
    need(not any(values[size:]),'SourcePadding')
    return values[:size]+[0]*max(0,size-len(values))


def source_view(v,digits,side,size):
    r.vector(digits,v['layout']['layout']['cells'])
    return extend(digits[side::4],size)


def output_view(v,words):
    r.vector(words,v['layout']['s'])
    return extend(words,v['a_slots'])


def source(v,digits):
    r.vector(digits,v['layout']['layout']['cells'])
    return [x for j in range(v['layout']['layout']['planes']) for x in (digits[4*j],digits[4*j+1],int(j==0),int(j==0))]


def witness(p,product,remainder):
    v=derive(p,4);need(type(product) is int and 0<=product<=v['cert']['MD_max'],'Product')
    need(type(remainder) is int and 0<=remainder<=v['remainder_max'],'Remainder')
    return lp.limbs.witness(v['sum'].schema,(product,remainder),(1,1))


def expected_roots(p,product,remainder,total):
    v=derive(p,4);witness(p,product,remainder);need(type(total) is int and 0<=total<1<<(8*v['a_slots']),'Scaled')
    return [r.root(identity,lp.limbs.digits(value,8,size)) for identity,value,size in
            ((p.product,product,v['md_slots']),(p.remainder,remainder,16),(p.output,total,v['a_slots']))]


def views(p,part,d):
    v=derive(p,d);need(type(part) is dict and type(part.get('input')) is dict and 'digits' in part['input'] and
                     type(part.get('output')) is dict and 'words' in part['output'],'ProofShape')
    digits,words=part['input']['digits'],part['output']['words'];roots=[]
    for name,identity,make in (('Product',p.product,lambda:source_view(v,digits,0,v['md_slots'])),
                               ('Remainder',p.remainder,lambda:source_view(v,digits,1,16)),('Scaled',p.output,lambda:output_view(v,words))):
        try: roots.append(r.root(identity,make()))
        except ValueError as error:raise ValueError(name+':'+str(error)) from None
    return roots+[lp.ls.source_root(v['layout']['input'],digits),lp.cr.source_root(v['layout']['output'],words)]


def transcript(v,roots,state,d):
    need(type(roots) is list and len(roots)==5 and all(type(x) is bytes and len(x)==32 for x in roots+[state]),'Root')
    return r.scalar.Transcript(v['raw']+b''.join(roots)+state,d)


def prepare(p,product,remainder,d):
    v=derive(p,d);return lp.prove(v['sum'],witness(p,product,remainder),d)


def assemble(p,pair,d):
    """Producer only; actual source/root consumers remain mandatory in verify."""
    v=derive(p,d);return dict(sum=pair[0]),transcript(v,views(p,pair[0],d),pair[1],d).state


def prove(p,product,remainder,d):
    return assemble(p,prepare(p,product,remainder,d),d)


def verify(p,expected,proof,d):
    v=derive(p,d);need(type(expected) is list and len(expected)==3 and all(type(x) is bytes and len(x)==32 for x in expected),'Root')
    need(type(proof) is dict and set(proof)=={'sum'},'ProofShape');part=proof['sum'];roots=views(p,part,d)
    for name,actual,target in zip(('Product','Remainder','Scaled'),roots,expected):need(actual==target,name+':CommitmentMismatch')
    try:
        digits=part['input']['digits'];need(digits==source(v,digits),'SourceJoin')
        result=lp.verify(v['sum'],roots[3:],part,d)
    except ValueError as error:raise ValueError('Sum:'+str(error)) from None
    t=transcript(v,roots,result['state'],d)
    return dict(state=t.state,sum=result,draws=dict(t.draws),account=result['account'])
