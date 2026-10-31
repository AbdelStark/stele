# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""RFC-0004 Draft A3/A6/A8: full row conversion within unchanged lookup domains."""
import copy
from dataclasses import replace
import hashlib
import json
import sys
import row_code as dynamic
import static_row_code as static

r=dynamic.r


def rejects(reason,call):
    try:call()
    except ValueError as error:assert str(error)==reason,(reason,str(error))
    else:raise AssertionError('accepted '+reason)


def spec(mode,kind,count,identity=2751,repetitions=1,scale=65535):
    c=dynamic if mode=='dynamic' else static
    schema=static.row.Spec(kind,count,30,mode,0 if mode=='dynamic' else scale)
    return c,c.Spec(schema,identity,101,103,107,repetitions)


def ranges(c,p,d):
    v=c.derive(p,d);output=c.ss.derive(v['output'],d)['ranges']
    if c is static:return c.ss.derive(v['input'],d)['ranges']+output+[v[name] for name in c.RANGES]
    sv=c.ds.derive(v['scale'],d);mv=c.ds.am.derive(sv['maximum'],d)
    return c.ss.derive(mv['input'],d)['ranges']+[mv[name] for name in ('maximum','gap','indicator')]+[sv[name] for name in ('scale','slack','carry')]+output+[v[name] for name in c.RANGES]


def reference(p,xs):
    s=(max(map(abs,xs))+126)//127 if p.schema.mode=='dynamic' else p.schema.scale
    codes=[]
    for x in xs:
        q,rem=divmod(abs(x),s) if s else (0,0);q+=int(s>0 and 2*rem>=s)
        assert q<=127;codes.append(-q if x<0 else q)
    return s,codes


def expected(p,xs):
    s,codes=reference(p,xs);n=1<<(len(xs)-1).bit_length();width=2 if p.schema.kind=='wide' else 4
    raw=[x%(1<<(8*width)) for x in xs]+[0]*(n-len(xs))
    return [r.root(p.source,[x>>(8*j)&255 for j in range(width) for x in raw]),
        r.root(p.scale,list(s.to_bytes(width,'little'))),r.root(p.output,[x%256 for x in codes]+[0]*(n-len(xs)))]


def inputs(p):
    h=32768 if p.schema.kind=='wide' else 1<<30;high=h-1 if p.schema.kind=='wide' else h
    if p.schema.mode=='static':h=min(h,(255*p.schema.scale-1)//2);high=min(high,h)
    return [(-h,high,-1,0,1)[i%5] for i in range(p.schema.dimension)]


def shapes():
    digest=hashlib.sha256();cases=cells=0
    for kind in ('wide','gated'):
        for mode,scale in (('dynamic',0),('static',1),('static',257),('static',65535)):
            for count in (1025,2049,8193,16383,16384):
                c,p=spec(mode,kind,count,(1<<(36 if mode=='dynamic' else 44))-1,2,scale)
                for d in (4,8):
                    v=c.derive(p,d);children=ranges(c,p,d)
                    assert len(children)==(19 if c is dynamic else 9)
                    for child in children:
                        a,b,n,w,_,_=r.derive(child,d)
                        assert len(child.caps)<=65536 and n*w<=131072 and a+b+1<=18
                    assert v['base']+(1<<(26 if c is dynamic else 18))==(1<<63)+(1<<62)
                xs=inputs(p);w=c.witness(p,xs);s,codes=reference(p,xs);n,planes=v['n'],v['planes']
                assert w['codes']==codes and w['carry'][-n:]==[3]*n and all(0<=x<=258 for x in w['carry'])
                if c is dynamic:assert w['scale']==s
                for i in range(n):
                    mag=abs(xs[i]) if i<count else 0;q=w['quotient'][i] if i<count else 0
                    rem=w['remainder'][i] if i<count else 0;si=s if i<count else 0
                    for j in range(planes):
                        incoming=w['carry'][(j-1)*n+i] if j else 3;sb=si>>(8*j)&255
                        assert 2*sb*q+(rem>>(8*j)&255)+incoming+765==2*(mag>>(8*j)&255)+sb+256*w['carry'][j*n+i]
                digest.update(v['raw']+b''.join(expected(p,xs)));cases+=1;cells+=n*planes
            bad=replace(p,schema=replace(p.schema,dimension=16385))
            rejects('Capacity',lambda:c.witness(bad,None));rejects('Capacity',lambda:c.verify(bad,None,None,4))
    for kind in ('wide','gated'):
        c,p=spec('dynamic',kind,16384);w=c.witness(p,[0]*16384)
        assert w['scale']==0 and w['codes']==[0]*16384 and w['carry']==[3]*65536
        rejects('Capacity',lambda:c.ds.witness(replace(c.derive(p,4)['scale'],schema=replace(p.schema,dimension=16385)),None))
    assert cases==40 and cells==1548288 and digest.hexdigest()=='9e7621992ac1de560d6a5e2d7477ec0b23ec8c1666f4c50aee279a39bdb907dc'
    print(json.dumps(dict(shape_cases=cases,zero_cases=2,column_cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def account(c,p,out,d):
    v=c.derive(p,d);a,b,k=v['a'],v['b'],v['c'];f=lambda m:3*m*(m-1)//2+2*m
    if c is dynamic:
        dims=[a+b+1,a+b+1,a+2,b+1,a+b+1,a+1,b+1,1,b+1,a+1,a+1,a+2,a+1,a+b+1,a+b+1,a+1,1,b+1,a+k+2]
        numerator=171*a+87*b+12*k+25;selection=dict(selection_reduction_numerator=a);parent=5*a+k
        scale,output=out['children'][:2];maximum=scale['children'][0];source=maximum['children'][0]
        children=source['ranges']+maximum['children'][1:]+scale['children'][1:]+output['ranges']+out['children'][2:]
        draws=[out['draws'],scale['draws'],maximum['draws'],source['draws'],output['draws']]+[x['draws'] for x in children]
        totals=(73*a+36*b+5*k+11,74*a+36*b+5*k+11)
        offsets=(32,5,33,5,33,34,35,36,37,1,4,36,38,39,40,41,42,43,44,45,46,1)
        assert sum(x['numerator'] for x in out['sc'])==12*a+3*k
        assert len(maximum['claims'])==9 and maximum['one']['sc']['numerator']==a
    else:
        br=v['br'];dims=[a+b+1,a+b+1,a+2,a+1,a+1,a+2,a+1,a+br+1,a+k+2]
        numerator=121*a+26*b+7*br+12*k+25;selection={};parent=3*a+k
        source,output=out['children'][:2];children=source['ranges']+output['ranges']+out['children'][2:]
        draws=[out['draws'],source['draws'],output['draws']]+[x['draws'] for x in children]
        totals=(51*a+10*b+3*br+5*k+11,)*2;offsets=(16,17,18,19,20,21,22,23,24,2)
        assert sum(x['numerator'] for x in out['sc'])==8*a+3*k
    assert out['account']==dict(identities=[((1<<m)+255,p.repetitions) for m in dims],lookup_reduction_numerator=sum(p.repetitions*(f(m)+f(8)+3*m) for m in dims),range_reduction_numerator=numerator,denominator=r.sc.P**d,**selection)
    assert out['draws']=={r.zc.WEIGHT:parent,r.zc.tr.CHALLENGE:parent}
    assert [claim[0] for claim in out['claims']]==[v['base']+j for j in offsets]
    assert len(source['claims'])==len(output['claims'])==16
    for label,total in zip((r.zc.WEIGHT,r.zc.tr.CHALLENGE),totals):assert sum(x.get(label,0) for x in draws)==total
    for child,m in zip(children,dims):
        assert child['account']['identity_numerator']==(1<<m)+255 and child['account']['identity_power']==p.repetitions
        assert child['account']['lookup_reduction_numerator']==p.repetitions*(f(m)+f(8)+3*m)
        assert len(child['claims'])==9 and len(child['lookup_claims'])==2*p.repetitions


def run(mode,kind,count,d,repetitions):
    c,p=spec(mode,kind,count,2752,repetitions);xs=inputs(p);roots=expected(p,xs)
    print('conversion start',mode,kind,count,d,repetitions,flush=True)
    proof,state=c.prove(p,xs,d);out=c.verify(p,roots,proof,d)
    assert out['state']==state and c.roots(p,proof)==roots;account(c,p,out,d)
    bad=copy.deepcopy(proof);source=bad['scale']['maximum']['input'] if c is dynamic else bad['input']
    source['ranges'][0]['words'][count-1]^=1
    reason='Scale:Maximum:Input:Raw:CommitmentMismatch' if c is dynamic else 'Input:Raw:CommitmentMismatch'
    rejects(reason,lambda:c.verify(p,roots,bad,d))
    print('conversion passed',mode,kind,count,d,repetitions,flush=True);return state


def honest():
    digest=hashlib.sha256();cases=0
    for d in (4,8):
        for repetitions in (1,2):
            for mode in ('dynamic','static'):
                for kind in ('wide','gated'):
                    digest.update(run(mode,kind,65,d,repetitions));cases+=1
    assert cases==16 and digest.hexdigest()=='49bfeb69d3c8312dd2f4b3e11ccb740906bb31d9f84eec1eccdd759103dcae82'
    print(json.dumps(dict(proofs=cases,maximum=False,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def full(mode,kind,d,repetitions):
    state=run(mode,kind,16384,d,repetitions)
    print(json.dumps(dict(mode=mode,kind=kind,count=16384,field=d,repetitions=repetitions,maximum=True,state=state.hex()),sort_keys=True),flush=True)


if __name__=='__main__':
    modes={'--shapes':shapes,'--honest':honest,'--maximum':lambda:full('dynamic','wide',4,2),
        '--full-static':lambda:full('static','wide',8,1),'--full-gated':lambda:full('dynamic','gated',8,1),
        '--full-static-gated':lambda:full('static','gated',4,2)}
    selected=sys.argv[1:] or ['--shapes','--honest'];assert all(mode in modes for mode in selected)
    for mode in selected:modes[mode]()
