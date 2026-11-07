"""Draft RFC-0025: Artifact-backed full/cache model execution against exact oracles."""
from dataclasses import replace
from fractions import Fraction as Q
from functools import lru_cache
from hashlib import sha256
import json
from random import Random
from struct import pack

from blake3 import blake3
from flint import arb, ctx

from check_arithmetic_bounds import rejects
from check_artifact_codec import artifact, mapping
from check_decoding_execution import exp_oracle, oracle as decode_oracle, seed_hash
from check_model_codec import make, roles
from check_numerics import nearest
from function_bounds import Activation, Exponential
from model_codec import Rotation, Sampled
from request_bounds import Request
from scales_codec import Scale, encode as encode_scales
from source_map import Shape
import model_execution as c
from check_rope import oracle as rotary_oracle


def fixture(rng,family,layers=None,context=None,heads=None,width=None,version=1,group=False):
    heads=heads or rng.randint(1,2); width=width or rng.choice((2,4)); d=heads*width
    s=Shape(family,layers or rng.randint(1,3),d,heads,heads if not family else rng.choice((1,heads)),width,
            4*d if not family else rng.randint(1,8),rng.randint(2,7),context or rng.randint(2,6))
    m=make(rng,family,s); expmode=rng.randrange(3); exp=Exponential(s.context,15,6,6,expmode,7 if expmode else 0)
    def norm(n,fraction):
        kw=dict(F=fraction,G=6,E=6,en=1,ed=100000)
        if not family: kw['Gb']=6
        return replace(n,**kw)
    blocks=[]; f0=rng.randint(6,8); incoming=f0
    for b in m.blocks:
        mode=rng.randrange(3); rotation=None if not family else Rotation(width,s.context,mode,rng.randrange(2),8192 if mode==2 else 0,
            ((500000,1),(1 if mode==0 else 8,1),(1 if mode==2 else 0,1),(4 if mode==2 else 0,1)))
        policies=tuple((1,rng.choice((1,3,17))) if rng.randrange(3)==0 else (0,0) for _ in range(7))
        accumulation=rng.randrange(2)
        fractions=tuple(rng.randint(6,8) for _ in range(7 if family else 6)); mid,out=rng.randint(6,8),rng.randint(6,8)
        blocks.append(replace(b,norm1=norm(b.norm1,incoming),norm2=norm(b.norm2,mid),fractions=fractions,mid=mid,out=out,
            attention=rng.randint(6,8),policies=policies,score_m=1,score_e=-4,accumulation=accumulation,drop=17 if accumulation else 0,
            exp=exp,activation=Activation(s.hidden,1 if family else 4,fractions[5 if family else 4],6),rotation=rotation))
        incoming=out
    decoding=Sampled(1,1,1,rng.choice((1,2)),replace(exp,n=s.vocabulary)) if rng.randrange(2) else None
    formats=tuple((rng.choice((4,8)),0) if len(ds)==2 else (16,6) for _,_,ds in roles(s))
    m=replace(m,formats=formats,f0=f0,blocks=tuple(blocks),final_norm=norm(m.final_norm,incoming),final_policy=(0,0),logits_fraction=rng.randint(6,8),decoding=decoding)
    if version==2:  # RFC-0004 A14 wide twin: same draws, every rmsnorm_q at version 2
        v=lambda n: replace(n,version=2)
        m=replace(m,blocks=tuple(replace(b,norm1=v(b.norm1),norm2=v(b.norm2)) for b in m.blocks),final_norm=v(m.final_norm))
    if group:  # RFC-0004 A15 grouped twin: same draws, dynamic affine-input rows grouped
        m=replace(m,blocks=tuple(replace(b,policies=tuple(grouped(p,n) for p,n in zip(b.policies,(d,0,0,0,d,d,s.hidden)))) for b in m.blocks),
                  final_policy=grouped(m.final_policy,d))
    arrays={}; scales=[]; payload=[]
    for (name,layer,ds),(bits,_) in zip(roles(s),formats):
        n=ds[0]*(ds[1] if len(ds)==2 else 1)
        if len(ds)==2:
            codes=tuple(rng.randint(-3,3) for _ in range(n)); e=-3 if name in ('token','position') else 0 if name in ('up','gate') else -4
            mantissas=tuple(rng.randint(1,3) for _ in range(ds[0])); scales.append(Scale(e,b''.join(pack('<H',x) for x in mantissas)))
            arrays[name,layer]=(ds,e,mantissas,codes)
            if bits==8: raw=b''.join(pack('<b',x) for x in codes)
            else:
                digits=tuple(x%16 for x in codes)+( (0,) if n%2 else ())
                raw=bytes(a+16*b for a,b in zip(digits[::2],digits[1::2]))
        else:
            codes=tuple(rng.randint(48,80) if name.endswith('gain') else rng.randint(-32,32) for _ in range(n))
            arrays[name,layer]=(ds,codes); raw=b''.join(pack('<h',x) for x in codes)
        payload.append(raw)
    mp=mapping(m,rng,False); sr=encode_scales(m,tuple(scales)); raw=artifact(m,mp,tuple(scales),payload)
    return m,mp,sr,raw,arrays


def grouped(policy,n):
    """The largest power-of-two group size below n that divides n; static and n<=1 rows stay."""
    return (2,n&-n if n&(n-1) else n//2) if policy==(0,0) and n>1 else policy


def wide(value):
    x=nearest(value)
    if not -32768<=x<=32767: raise ValueError('Range')
    return x


def qrow(values,fraction,policy):
    if policy[0]==2:  # RFC-0004 A15: an independent dynamic conversion of each group of g
        g=policy[1]; parts=[qrow(values[i:i+g],fraction,(0,0)) for i in range(0,len(values),g)]
        return sum((p[0] for p in parts),()),tuple(p[1] for p in parts),fraction
    s=policy[1] if policy[0] else (max(map(abs,values))+126)//127
    codes=tuple(nearest(Q(x,s)) for x in values) if s else (0,)*len(values)
    if any(abs(x)>127 for x in codes): raise ValueError('RowRange')
    return codes,s,fraction


def linear(a,name,layer,x,fo,family,head=False):
    ds,e,m,weights=a[('head' if family else 'token',-1) if head else (name,layer)]; codes,s,f=x
    bias=(0,)*ds[0] if family or head else a[name+'.bias',layer][1]
    scale=(lambda k:s[k*len(s)//ds[1]]) if type(s) is tuple else (lambda k:s)  # grouped: s of k's group
    return tuple(wide(sum(Q(weights[j*ds[1]+k]*codes[k]*m[j]*scale(k))*Q(2)**(e-f+fo) for k in range(ds[1]))+Q(bias[j])*Q(2)**(fo-6)) for j in range(ds[0]))


@lru_cache(maxsize=49152)
def rsqrt(mantissa):
    with ctx.workprec(256):
        j=((arb(2**42)/mantissa).sqrt()+arb(1)/2).floor().unique_fmpz(); assert j is not None
        return int(j)


def norm(n,x,g,bias):
    mean=Q(0) if isinstance(n,c.RMSNorm) else sum(map(Q,x))/len(x)
    q=sum((Q(v)-mean)**2 for v in x)/len(x)/2**(2*n.F)+Q(n.en,n.ed)
    exponent=next(k for k in range(-23,10) if 16384<=q/Q(4)**k<65536)
    mantissa=q/Q(4)**exponent; mantissa=mantissa.numerator//mantissa.denominator
    j=rsqrt(mantissa)
    return tuple(wide((Q(v)-mean)*gain*j*Q(2)**(n.E-n.F-n.G-21-exponent)+Q(b)*Q(2)**(n.E-6)) for v,gain,b in zip(x,g,bias))


rotary_point=lru_cache(maxsize=65536)(rotary_oracle)
exp_point=lru_cache(maxsize=65536)(exp_oracle)


def rotate(r,values,position,heads,width):
    if r is None: return values
    ratios=tuple(Q(*q) for q in r.rationals)
    p=c.rope.Parameters(r.width,r.length,ratios[0],('base','linear','llama3')[r.family],('adjacent','split')[r.layout],*ratios[1:],r.original)
    result=list(values)
    for h in range(heads):
        for j in range(r.width//2):
            cosine,sine=(v[0] for v in rotary_point(p,position,j)); i=h*width+(2*j if r.layout==0 else j); k=i+1 if r.layout==0 else i+r.width//2
            result[i]=wide(Q(values[i]*cosine-values[k]*sine,16384)); result[k]=wide(Q(values[i]*sine+values[k]*cosine,16384))
    return tuple(result)


@lru_cache(maxsize=65536)
def activation(p,value):
    if value==0:return 0
    sign=-1 if value<0 else 1; limit=Q(abs(value))*Q(2)**(p.E-p.F)
    for precision in (256,512,1024):
        with ctx.workprec(precision):
            x=arb(value)/2**p.F
            real=x/(1+(-x).exp()) if p.kind==1 else x*(1+((arb(2)/arb.pi()).sqrt()*(x+arb(8943)/200000*x**3)).tanh())/2
            magnitude=sign*real*2**p.E
            low=max(Q(0),Q(str(magnitude.lower().fmpq()))); high=min(limit,Q(str(magnitude.upper().fmpq())))
        assert 0<=low<=high<=limit,'OracleInterval'
        lower=low+Q(1,2); upper=high+Q(1,2)
        a=lower.numerator//lower.denominator; b=upper.numerator//upper.denominator
        # RFC-0021 §2.2: for nonzero finite x, 0<|f(x)|<|x|; the upper endpoint is open.
        if high==limit and upper.denominator==1:b-=1
        if a==b:
            result=sign*a
            if not -32768<=result<=32767:raise ValueError('Range')
            return result
    raise AssertionError('OraclePrecision')


def activation_tail_boundaries():
    cases=((4,7,6,1783,891),(1,1,0,513,256),(1,7,6,32767,16383))
    for kind,f,e,value,expected in cases:
        p=Activation(1,kind,f,e)
        assert activation(p,value)==expected==c.activation(p,value)
        assert activation(p,-value)==0==c.activation(p,-value)
    return 2*len(cases)


def reference(m,a,tokens):
    s=m.shape; rows=[]
    for p,t in enumerate(tokens):
        ds,e,ms,ws=a['token',-1]; values=[Q(ws[t*s.width+j]*ms[t])*Q(2)**(e+m.f0) for j in range(s.width)]
        if not s.family:
            ds,e,ms,ws=a['position',-1]; values=[v+Q(ws[p*s.width+j]*ms[p])*Q(2)**(e+m.f0) for j,v in enumerate(values)]
        rows.append(tuple(map(wide,values)))
    cuts=[tuple(rows)]; cache=[]
    for layer,b in enumerate(m.blocks):
        projections=[]
        for position,row in enumerate(rows):
            first=norm(b.norm1,row,a['norm1.gain',layer][1],(0,)*s.width if s.family else a['norm1.bias',layer][1]); x=qrow(first,b.norm1.E,b.policies[0])
            q,k,v=(linear(a,name,layer,x,b.fractions[j],s.family) for j,name in enumerate(('Q','K','V')))
            q=rotate(b.rotation,q,position,s.heads,s.head_width); k=rotate(b.rotation,k,position,s.groups,s.head_width)
            projections.append(tuple(qrow(values,b.fractions[j],b.policies[j+1]) for j,values in enumerate((q,k,v))))
        cache.append(tuple((p[1],p[2]) for p in projections)); outputs=[]
        for position,row in enumerate(rows):
            q=projections[position][0]; attention=[]
            for head in range(s.heads):
                group=head//(s.heads//s.groups); scores=[]
                for k,v in cache[-1]:
                    dot=sum(q[0][head*s.head_width+j]*k[0][group*s.head_width+j] for j in range(s.head_width))
                    scores.append(nearest(Q(dot*q[1]*k[1]*b.score_m)*Q(2)**(b.score_e-b.fractions[0]-b.fractions[1]+b.exp.F)))
                maximum=max(scores[:position+1])
                if any(x-maximum<-2**b.exp.bits for x in scores[:position+1]): raise ValueError('ExpDomain')
                weights=[exp_point(b.exp,x-maximum) for x in scores[:position+1]]
                for lane in range(s.head_width):
                    terms=[weight*pair[1][1]*pair[1][0][group*s.head_width+lane] for weight,pair in zip(weights,cache[-1])]
                    total=sum(nearest(Q(sum(terms[i:i+1024]),2**b.drop)) for i in range(0,len(terms),1024)) if b.accumulation else sum(terms)
                    attention.append(wide(Q(total,sum(weights))*Q(2)**(b.attention-b.fractions[2]+b.drop)))
            o=linear(a,'O',layer,qrow(attention,b.attention,b.policies[4]),b.fractions[3],s.family)
            incoming=m.f0 if layer==0 else m.blocks[layer-1].out
            mid=tuple(wide(Q(x)*Q(2)**(b.mid-incoming)+Q(y)*Q(2)**(b.mid-b.fractions[3])) for x,y in zip(row,o))
            second=norm(b.norm2,mid,a['norm2.gain',layer][1],(0,)*s.width if s.family else a['norm2.bias',layer][1])
            x=qrow(second,b.norm2.E,b.policies[5]); up=linear(a,'up',layer,x,b.fractions[4],s.family)
            gate=linear(a,'gate',layer,x,b.fractions[5],s.family) if s.family else up
            activated=tuple(activation(b.activation,t) for t in gate); product=tuple(x*y for x,y in zip(up,activated)) if s.family else activated
            down=linear(a,'down',layer,qrow(product,b.activation.E+(b.fractions[4] if s.family else 0),b.policies[6]),b.fractions[-1],s.family)
            outputs.append(tuple(wide(Q(x)*Q(2)**(b.out-b.mid)+Q(y)*Q(2)**(b.out-b.fractions[-1])) for x,y in zip(mid,down)))
        rows=outputs; cuts.append(tuple(rows))
    logits=[]
    for row in rows:
        final=norm(m.final_norm,row,a['final.gain',-1][1],(0,)*s.width if s.family else a['final.bias',-1][1])
        logits.append(linear(a,'head',-1,qrow(final,m.final_norm.E,m.final_policy),m.logits_fraction,s.family,True))
    return tuple(cuts),tuple(logits),tuple(cache)


def compare(m,mp,sr,raw,a,tokens,expected=None):
    data=c.load(m,mp,sr,raw,blake3(raw).digest()); expected=reference(m,a,tokens) if expected is None else expected; full=c.full(data,tokens)
    assert (full.cuts,full.logits)==expected[:2]
    actual_cache=tuple(tuple(((k.codes,k.scale,k.fraction),(v.codes,v.scale,v.fraction)) for k,v in layer) for layer in full.cache.layers)
    assert actual_cache==expected[2]
    state=None; columns=[]; heads=[]
    for token in tokens:
        row,state=c.step(data,token,state); columns.append(row.cuts); heads.append(row.logits)
    assert tuple(tuple(column[i] for column in columns) for i in range(len(m.blocks)+1))==full.cuts
    assert tuple(heads)==full.logits and state==full.cache
    return data,full


def generation_reference(m,a,boundary,prompt,seed):
    sequence=prompt; result=reference(m,a,sequence); reason=0
    for _ in range(boundary.maximum_new):
        decision=decode_oracle(m,boundary,sequence,result[1][-1],seed)
        sequence+=(decision.token,); result=reference(m,a,sequence)
        if decision.token in boundary.eos: reason=1; break
    return sequence,reason,result


def generation_case(data,a,prompt,rng):
    m=data.model; seed=None if m.decoding is None else rng.randbytes(32)
    boundary=Request(len(prompt),rng.randint(0,m.shape.context-len(prompt)),(m.shape.vocabulary-1,),None if seed is None else seed_hash(seed))
    try: expected=generation_reference(m,a,boundary,prompt,seed)
    except ValueError as error:
        assert str(error) in ('Range','RowRange','ExpDomain'); rejects(lambda:c.generate(data,boundary,prompt,seed),str(error))
        return 'reject',str(error)
    sequence,reason,cache=c.generate(data,boundary,prompt,seed); assert (sequence,reason)==expected[:2]
    final=c.full(data,sequence); assert (final.cuts,final.logits)==expected[2][:2] and cache==final.cache
    return 'eos' if reason else 'zero' if boundary.maximum_new==0 else 'limit',[sequence,reason]


def block_boundary():
    rng=Random(26923); m,mp,sr,raw,a=fixture(rng,1,layers=1,context=2048,heads=1,width=2)
    from scales_codec import decode
    values=decode(m,sr); b=replace(m.blocks[0],accumulation=1,drop=17,policies=((0,0),)*7,attention=6,
        fractions=(6,)*7,activation=Activation(m.shape.hidden,1,6,6)); m=replace(m,blocks=(b,))
    data=c.load(m,mp,encode_scales(m,values),raw,blake3(raw).digest()); zero=c.Row((0,0),0,6)
    for sign in (-1,1):
        keys=tuple((zero,c.Row((sign*(100 if j==1024 else 1),)*2,1,6)) for j in range(2048))
        for pos in (1,1023,1024):
            result=c.attend(data,0,zero,pos,keys); assert result==c.attend(data,0,zero,pos,keys[:pos+1])
            expected=(sign*2,)*2 if pos>=1023 else (0,0); assert result==expected
        exact=replace(m,blocks=(replace(b,accumulation=0,drop=0),)); ed=c.load(exact,mp,encode_scales(exact,values),raw,blake3(raw).digest())
        assert c.attend(ed,0,zero,1024,keys)==(sign,sign)
    return dict(key_capacity=2048,query_positions=[1,1023,1024],signed_cases=2)


def rebuild(m,a,rng):
    scales=[]; payloads=[]
    for (name,layer,ds),(bits,_) in zip(roles(m.shape),m.formats):
        item=a[name,layer]; codes=item[-1]
        if len(ds)==2: scales.append(Scale(item[1],b''.join(pack('<H',v) for v in item[2])))
        if bits==16: raw=b''.join(pack('<h',v) for v in codes)
        elif bits==8: raw=bytes(x%256 for x in codes)
        else: raw=bytes(codes[i]%16+16*(codes[i+1]%16 if i+1<len(codes) else 0) for i in range(0,len(codes),2))
        payloads.append(raw)
    mp=mapping(m,rng,False); sr=encode_scales(m,tuple(scales)); raw=artifact(m,mp,tuple(scales),payloads)
    return mp,sr,raw


def atomic_failure():
    rng=Random(26925); m,_,_,_,_=fixture(rng,1,layers=1,context=3,heads=1,width=2)
    m=replace(m,decoding=None,blocks=tuple(replace(b,policies=((0,0),)*7) for b in m.blocks)); a={}
    for name,layer,ds in roles(m.shape):
        if len(ds)==1: a[name,layer]=(ds,(64,)*ds[0]); continue
        count=ds[0]*ds[1]; codes=(0,)*count; scales=(1,)*ds[0]; exponent=0
        if name=='token': codes=(1,)*count; scales=(1,65535)+(1,)*(ds[0]-2)
        if name=='head': codes=(0,)*ds[1]+(1,)*ds[1]+(0,)*(count-2*ds[1]); exponent=-4
        a[name,layer]=(ds,exponent,scales,codes)
    mp,sr,raw=rebuild(m,a,rng); data=c.load(m,mp,sr,raw,blake3(raw).digest()); first=c.full(data,(0,)); original=first.cache
    assert first.logits[0].index(max(first.logits[0]))==1
    rejects(lambda:c.step(data,1,original),'Range'); assert original==first.cache and original.tokens==(0,)
    rejects(lambda:c.generate(data,Request(1,1,(1,),None),(0,),None),'Range')
    record=data.record('token'); at=record.payload_offset; changed=raw[:at]+bytes((raw[at]&240 if record.bits==4 else 0,))+raw[at+1:]
    rejects(lambda:c.load(m,mp,sr,changed,blake3(raw).digest()),'Identity')
    other=c.load(m,mp,sr,changed,blake3(changed).digest()); rejects(lambda:c.step(other,0,original),'CacheScope')
    late=dict(a); ds,_,_,codes=late['token',-1]
    late['token',-1]=(ds,0,(1,)*ds[0],(0,)*ds[1]+(1,)*ds[1]+(0,)*(len(codes)-2*ds[1]))
    ds,_,ms,codes=late['head',-1]; late['head',-1]=(ds,1024,ms,codes)
    lmp,lsr,lraw=rebuild(m,late,rng); ld=c.load(m,lmp,lsr,lraw,blake3(lraw).digest()); initial=c.full(ld,(0,)); old=initial.cache
    row=c.embed(ld,1,1); projected=c.project(ld,0,row,1)
    row=c.finish_block(ld,0,row,1,projected,old.layers[0]+((projected[1],projected[2]),))
    rejects(lambda:c.finish(ld,row),'Range')
    rejects(lambda:c.step(ld,1,old),'Range'); assert old==initial.cache and old.tokens==(0,)
    return dict(late_output_atomic=True,eos_evaluated_before_stop=True,artifact_substitution_rejected=True)


def large_artifact():
    rng=Random(26926); m,_,_,_,_=fixture(rng,1,layers=1,context=2,heads=1,width=6); v=699051
    m=replace(m,shape=replace(m.shape,vocabulary=v),decoding=None,formats=tuple((8,0) if bits!=16 else (bits,f) for bits,f in m.formats),
              blocks=tuple(replace(b,policies=((0,0),)*7) for b in m.blocks)); a={}; index=2**22
    for name,layer,ds in roles(m.shape):
        if len(ds)==1: a[name,layer]=(ds,(64,)*ds[0]); continue
        count=ds[0]*ds[1]; codes=(0,)*count
        if name in ('token','head'): codes=codes[:index]+(1,)+codes[index+1:]
        a[name,layer]=(ds,0,(1,)*ds[0],codes)
    mp,sr,raw=rebuild(m,a,rng); data=c.load(m,mp,sr,raw,blake3(raw).digest()); assert data.raw is raw
    token=index//6; lane=index%6; assert data.code(data.record('token'),index)==1
    result=c.full(data,(token,)); row=tuple(2**m.blocks[-1].out if j==lane else 0 for j in range(6))
    final=norm(m.final_norm,row,(64,)*6,(0,)*6); codes,scale,f=qrow(final,m.final_norm.E,m.final_policy)
    value=wide(Q(codes[lane]*scale)*Q(2)**(m.logits_fraction-f))
    assert result.logits==((0,)*(v-1)+(value,),) and value!=0
    assert result.cuts[-1]==(row,)
    return dict(token_elements=6*v,selected_element=index,vocabulary=v,artifact_bytes=len(raw),selected_logit=value)


def boundaries():
    rng=Random(26920); case=fixture(rng,0,layers=1); m,mp,sr,raw,a=case
    data,full=compare(*case,(0,1))
    rejects(lambda:c.load(m,mp,sr,raw,bytes(32)),'Identity')
    rejects(lambda:c.load(m,mp,sr,bytearray(raw),blake3(raw).digest()),'Artifact')
    rejects(lambda:c.full(data,()),'Length'); rejects(lambda:c.full(data,(True,)),'Token')
    rejects(lambda:c.step(data,0,replace(full.cache,scope=(bytes(32),)*3)),'CacheScope')
    rejects(lambda:c.step(data,0,replace(full.cache,layers=())),'Cache')
    # Scores and block admission depend on full configured domains, even for zero inputs.
    bad=replace(m,blocks=(replace(m.blocks[0],score_m=65535,score_e=30),))
    from scales_codec import decode
    ss=encode_scales(bad,decode(m,sr))
    rejects(lambda:c.load(bad,mp,ss,raw,blake3(raw).digest()),'ScoreBound')
    bad=replace(m,blocks=(replace(m.blocks[0],accumulation=1,drop=0),)); ss=encode_scales(bad,decode(m,sr))
    rejects(lambda:c.load(bad,mp,ss,raw,blake3(raw).digest()),'BlockBound')
    odd=fixture(rng,0,layers=1,heads=1,width=3)
    while odd[0].shape.vocabulary%2==0: odd=fixture(rng,0,layers=1,heads=1,width=3)
    om,_,_,_,oa=odd; om=replace(om,formats=tuple((4,0) if bits!=16 else (bits,f) for bits,f in om.formats)); omp,osr,oraw=rebuild(om,oa,rng)
    od=c.load(om,omp,osr,oraw,blake3(oraw).digest())
    for name,layer,_ in roles(om.shape):
        record=od.record(name,layer); assert tuple(od.code(record,i) for i in range(record.elements))==oa[name,layer][-1]
    return dict(cache_scope_controls=True,static_score_and_block_controls=True,odd_row_width=3,odd_token_elements=od.record('token').elements,
                activation_tail_cases=activation_tail_boundaries())


def main():
    rng=Random(2692); corpus=sha256(); counts=[0,0]; rejected=0; generations={key:0 for key in ('eos','zero','limit','reject')}
    for i in range(10000):
        case=fixture(rng,i%2); m,mp,sr,raw,a=case; tokens=tuple(rng.randrange(m.shape.vocabulary) for _ in range(rng.randint(1,m.shape.context)))
        try: expected=reference(m,a,tokens)
        except ValueError as error:
            assert str(error) in ('Range','RowRange','ExpDomain'); data=c.load(m,mp,sr,raw,blake3(raw).digest()); rejects(lambda:c.full(data,tokens),str(error)); rejected+=1; value=str(error)
        else:
            data,result=compare(*case,tokens,expected); counts[i%2]+=1; value=[result.cuts,result.logits]
        tag,generated=generation_case(data,a,tokens[:rng.randint(1,len(tokens))],rng); generations[tag]+=1
        corpus.update(blake3(raw).digest()+json.dumps([tokens,value,tag,generated],separators=(',',':')).encode())
        if (i+1)%1000==0: print(json.dumps(dict(completed=i+1)),flush=True)
    print(json.dumps(dict(seed=2692,configurations=10000,accepted_families=counts,rejected=rejected,generations=generations,corpus_sha256=corpus.hexdigest(),boundaries=boundaries(),blocks=block_boundary(),atomic=atomic_failure(),large=large_artifact()),sort_keys=True))


if __name__=='__main__': main()
