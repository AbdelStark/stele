"""Draft RFC-0025 §2.1/conversion appendix: exact bytes to streamed Artifact."""
from dataclasses import dataclass
from struct import pack, unpack_from

from blake3 import blake3

import artifact_codec as artifact
from numerics import integer
import scales_codec
import source_codec
import scalars

FORMATS=('binary16','bfloat16','binary32','binary64')


class _View:
    def __init__(self,entry,dimensions,tensor):
        self.entry,self.dimensions,self.data=entry,dimensions,tensor.data
        self.format=FORMATS[entry.dtype-1]; self.size=scalars.FORMATS[self.format][0]
        self.count=dimensions[0]*(dimensions[1] if len(dimensions)==2 else 1)

    def scalar(self,k):
        if not 0<=k<self.count: raise ValueError('Index')
        entry=self.entry; rows=self.dimensions[0]
        if entry.transform==0: index=k
        elif entry.transform==3: index=entry.part*rows+k
        else:
            row,column=divmod(k,self.dimensions[1])
            index=column*entry.shape[1]+row+(entry.part*rows if entry.transform==2 else 0)
        at=index*self.size
        if not 0<=at<=len(self.data)-self.size: raise ValueError('Index')
        return scalars.decode(self.format,bytes(self.data[at:at+self.size]))


def _maximum(a,b):
    # Exact dyadic comparison, including zeros and the full binary64 domain.
    p=min(a[1],b[1])
    return a if a[0]<<(a[1]-p)>=b[0]<<(b[1]-p) else b


def _ratio(n,shift,denominator):
    return (n<<shift,denominator) if shift>=0 else (n,denominator<<-shift)


def _rounded(n,shift,denominator):
    top,bottom=_ratio(abs(n),shift,denominator); quotient,remainder=divmod(top,bottom)
    return (quotient+int(2*remainder>=bottom))*(-1 if n<0 else 1)


def _scale(view,bits):
    q=(1<<(bits-1))-1; peak=(0,0)
    for k in range(view.count):
        n,p=view.scalar(k); peak=_maximum(peak,(abs(n),p))
    n,p=peak; exponent=0
    if n:
        bound=q*65535; exponent=n.bit_length()-bound.bit_length()+p
        top,bottom=_ratio(n,p-exponent,bound)
        exponent+=int(top>bottom)
    integer(exponent,-1099,1024,'Exponent')
    words=bytearray(); rows,columns=view.dimensions
    for row in range(rows):
        maximum=(0,0)
        for column in range(columns):
            n,p=view.scalar(row*columns+column); maximum=_maximum(maximum,(abs(n),p))
        n,p=maximum; top,bottom=_ratio(n,p-exponent,q)
        m=max(1,(top+bottom-1)//bottom); integer(m,1,65535,'Mantissa'); words.extend(pack('<H',m))
    return scales_codec.Scale(exponent,bytes(words))


def _codes(view,fmt,scale):
    bits,fraction=fmt
    if bits==16:
        for k in range(view.count):
            n,p=view.scalar(k); code=_rounded(n,p+fraction,1)
            integer(code,-32768,32767,'Overflow'); yield code
    else:
        rows,columns=view.dimensions; q=(1<<(bits-1))-1
        for row in range(rows):
            m=unpack_from('<H',scale.mantissas,2*row)[0]
            for column in range(columns):
                n,p=view.scalar(row*columns+column); code=_rounded(n,p-scale.exponent,m)
                integer(code,-q,q,'Overflow'); yield code


def _payload(view,fmt,scale):
    buffer=bytearray(); low=None; bits=fmt[0]
    for code in _codes(view,fmt,scale):
        if bits==16: buffer.extend(pack('<h',code))
        elif bits==8: buffer.append(code&255)
        elif low is None: low=code&15
        else: buffer.append(low|((code&15)<<4)); low=None
        if len(buffer)==artifact.CHUNK: yield bytes(buffer); buffer.clear()
    if low is not None: buffer.append(low)
    if buffer: yield bytes(buffer)


class _Reader:
    def __init__(self,chunks): self.chunks,self.pending,self.done=iter(chunks),b'',False
    def read(self,n):
        if not self.pending and not self.done:
            try: self.pending=next(self.chunks)
            except StopIteration: self.done=True
        value=self.pending[:n]; self.pending=self.pending[n:]; return value


@dataclass(frozen=True)
class Conversion:
    source_identity: bytes
    assets_id: bytes
    quantiser_id: bytes
    scales: bytes
    digest: bytes
    length: int


def convert(model,mapping,source,assets,files,sink):
    """Return only after complete emission; failed output must be discarded."""
    write=getattr(sink,'write',None)
    if not callable(write): raise ValueError('Sink')
    preparation=artifact.encode_preparation(model,mapping)
    package=source_codec.verify(mapping,source,assets,files)
    views=tuple(_View(entry,dims,package.tensors[entry.name])
                for entry,(_,_,dims) in zip(mapping.entries,model.shape.roles()))
    scales=[]; by_record=[]
    for view,fmt in zip(views,model.formats):
        if fmt[0]!=16:
            scale=_scale(view,fmt[0]); scales.append(scale)
        else:
            scale=None
            for _ in _codes(view,fmt,None): pass
        by_record.append(scale)
    raw=scales_codec.encode(model,tuple(scales))
    streams=tuple(_Reader(_payload(view,fmt,scale)) for view,fmt,scale in zip(views,model.formats,by_record))
    digest=blake3(); length=0
    for chunk in artifact.iterencode(model,mapping,raw,streams):
        written=write(chunk)
        if type(written) is not int or written!=len(chunk): raise ValueError('Write')
        length+=written; digest.update(chunk)
    return Conversion(package.source_identity,package.assets_id,blake3(preparation).digest(),raw,digest.digest(),length)
