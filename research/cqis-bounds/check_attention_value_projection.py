# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0"]
# ///
"""Draft RFC-0004 A3/A6: flat projection arithmetic, not source-proof credit."""
import hashlib
import json
import random
import sys
from attention_value_projection import EqProjector, r

sc=r.sc


def rejects(call):
    try:call()
    except ValueError as error:assert str(error)=='ProjectionShape',str(error)
    else:raise AssertionError('accepted invalid projection')


def dense(columns,start,n,point,d):
    out=[]
    for xs in columns:
        values=[sc.scalar(0,d)]*start+[sc.scalar(x,d) for x in xs]+[sc.scalar(0,d)]*(n-start-len(xs))
        for x in point:values=sc.fold(values,x)
        out.append(values[0])
    return out


def corpus():
    rng=random.Random(2760);digest=hashlib.sha256();rows=cells=0
    for d in (4,8):
        for case in range(10000):
            m=case%4;n=1<<m;point=[tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(m)]
            if case%5==0:point=[sc.scalar(rng.randrange(2),d) for _ in range(m)]
            projector=EqProjector(point,d);at=0
            while at<n:
                width=rng.randint(1,n-at);columns=[[rng.randrange(-sc.P,sc.P) for _ in range(width)] for _ in range(3)]
                actual=projector.row(columns);assert actual==dense(columns,at,n,point,d),(d,case,at)
                for x in actual:digest.update(sc.encode(x))
                rows+=1;cells+=width;at+=width
            assert projector.at==n
            rejects(lambda:projector.row([[0],[0],[0]]))
        for m in range(4,11):
            point=[tuple(rng.randrange(sc.P) for _ in range(d)) for _ in range(m)];n=1<<m;projector=EqProjector(point,d);at=0
            for width in (1,3,17,n-21) if n>=32 else (1,3,5,7):
                columns=[[rng.randrange(-256,65536) for _ in range(width)] for _ in range(3)]
                assert projector.row(columns)==dense(columns,at,n,point,d);at+=width
            assert at==n
        print('projection field passed',d,10000,flush=True)
    for point,d in (([],False),([],3),([tuple([0]*4)]*25,4),([[0]*4],4),([(sc.P,0,0,0)],4)):
        rejects(lambda:EqProjector(point,d))
    for columns in ([],[[1]],[[1],[1],[1,2]],[[True],[1],[1]],[[],[],[]],[[0.0],[1],[1]]):
        rejects(lambda:EqProjector([],4).row(columns))
    assert (rows,cells,digest.hexdigest())==(36540,75000,'df1424e9bff587280b74434f0084246230a7a814d9178bfd0f686cab89cbd4aa')
    print(json.dumps(dict(cases=20000,rows=rows,cells=cells,sha256=digest.hexdigest()),sort_keys=True),flush=True)


def full():
    m=24;width=16384;n=1<<m
    for d in (4,8):
        point=[tuple((11+i*13+j*17)%sc.P for j in range(d)) for i in range(m)];projector=EqProjector(point,d);sums=[sc.scalar(0,d)]*3
        for at in range(0,n,width):
            values=projector.row([[1]*width,list(range(at,at+width)),[(i>>7)&1 for i in range(at,at+width)]])
            sums=[sc.add(x,y) for x,y in zip(sums,values)]
        expected=[sc.scalar(1,d),r.zc.total((sc.mul(sc.scalar(1<<(m-i-1),d),x) for i,x in enumerate(point)),d),point[m-8]]
        assert sums==expected and projector.at==n
        assert sum(1<<k for k in projector.suffix)<2*width and len(projector.prefix)<=m+1
        print('full projection arithmetic passed',d,n,flush=True)


if __name__=='__main__':
    assert set(sys.argv[1:])<= {'--corpus','--full'}
    if '--corpus' in sys.argv or len(sys.argv)==1:corpus()
    if '--full' in sys.argv:full()
