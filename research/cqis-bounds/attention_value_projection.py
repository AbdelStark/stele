"""RFC-0006 A3 equality weights over flat intervals, without a full-domain table."""
from flint import nmod_mat
import wide_range as r


class EqProjector:
    def __init__(self,point,d):
        r.need(type(d) is int and d in (4,8) and type(point) is list and len(point)<=24 and all(type(x) is tuple and len(x)==d and all(type(y) is int and 0<=y<r.sc.P for y in x) for x in point),'ProjectionShape')
        self.point=point.copy();self.d=d;self.m=len(point);self.at=0;self.previous=0;self.suffix={};self.prefix=[r.sc.scalar(1,d)]

    def row(self,columns):
        r.need(type(columns) is list and len(columns)==3 and all(type(xs) is list for xs in columns) and len(columns[0])>0 and all(len(xs)==len(columns[0]) and all(type(x) is int for x in xs) for xs in columns) and self.at+len(columns[0])<=1<<self.m,'ProjectionShape')
        sc=r.sc;d=self.d;out=[sc.scalar(0,d)]*3;offset=0;width=len(columns[0])
        while offset<width:
            start=self.at+offset;k=(width-offset).bit_length()-1
            if start:k=min(k,(start&-start).bit_length()-1)
            size=1<<k;depth=self.m-k;common=self.m-(self.previous^start).bit_length();keep=min(common,depth,len(self.prefix)-1)
            del self.prefix[keep+1:]
            for i in range(keep,depth):
                weight=self.point[i] if start>>(self.m-i-1)&1 else sc.add(sc.scalar(1,d),sc.neg(self.point[i]))
                self.prefix.append(sc.mul(self.prefix[-1],weight))
            self.previous=start
            if k not in self.suffix:
                weights=r.scalar.eq_weights(self.point[depth:],d);self.suffix[k]=nmod_mat(size,d,[x for weight in weights for x in weight],sc.P)
            projected=nmod_mat(3,size,[x%sc.P for xs in columns for x in xs[offset:offset+size]],sc.P)*self.suffix[k]
            for j in range(3):out[j]=sc.add(out[j],sc.mul(self.prefix[-1],tuple(int(projected[j,i]) for i in range(d))))
            offset+=size
        self.at+=width;return out
