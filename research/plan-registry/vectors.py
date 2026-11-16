# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0026 A16 reference vectors; no accepting verifier or executed control credit.

Reuses the existing CQIS reference codecs; takes repository and A15 dump paths.
Print the canonical JSON and compare with vectors.json (see README.md).
"""
import json
import struct
import sys
from pathlib import Path
from blake3 import blake3

ROOT = Path(sys.argv[1])
DUMP = Path(sys.argv[2])
sys.path.insert(0, str(ROOT / 'research/cqis-model-contract'))
from model_codec import decode as model_decode
from scales_codec import decode as scales_decode


def u32(n): return struct.pack('<I', n)
def u64(n): return struct.pack('<Q', n)
def blob(x): return u32(len(x)) + x
def digest(x): return blake3(x).digest()


class Reader:
    def __init__(self, raw): self.raw, self.at = raw, 0
    def take(self, n):
        assert 0 <= n <= len(self.raw) - self.at
        out = self.raw[self.at:self.at+n]; self.at += n
        return out
    def number(self, fmt): return struct.unpack('<'+fmt, self.take(struct.calcsize('<'+fmt)))[0]
    def blob(self): return self.take(self.number('I'))


def columns(raw):
    r = Reader(raw)
    assert r.take(31) == b'stele/v0.1/relation/encoding/v1'
    for _ in range(r.number('I')): r.blob(); r.take(1)
    out = []
    for _ in range(r.number('I')):
        name, kind = r.blob().decode(), r.number('B')
        start, vals = None, None
        if kind == 0: r.take(4)
        elif kind == 2:
            count = r.number('I'); start = r.at
            vals = [r.number('q') for _ in range(count)]
        else: assert kind == 1
        width_at = r.at
        signed, width, log = r.take(3)
        out.append((name, kind, signed, width, log, vals, start, width_at))
    return out


def requests(V, d, ee, f0, ms, xs, begin, end, y):
    lt, lv, ld = (len(xs).bit_length()-1, (V-1).bit_length(), (d-1).bit_length())
    lb = min(lt, 30-ld-lv); B, Vp = 1 << lb, 1 << lv
    out = {}
    for b in range(len(xs)//B):
        out[f'G/embedding/O{b}'] = (1, lb+lv, [int(v == xs[b*B+i]) for i in range(B) for v in range(Vp)])
    shift = ee+f0
    values = [ms[x] if shift < 0 else (65536 if shift >= 17 else min(ms[x] << shift, 65536)) for x in xs]
    out['G/embedding/'+('m' if shift < 0 else 'mm')] = (max(values).bit_length(), lt, values)
    onehot, below = [], []
    for i in range(len(xs)):
        c = (xs[i+1] if i+1 < len(xs) else y) if begin <= i < end else None
        onehot.extend(int(c is not None and v < V and v == c) for v in range(Vp))
        below.extend(int(c is not None and v < V and v < c) for v in range(Vp))
    out['G/argmax/onehot'] = (1, lt+lv, onehot)
    out['G/argmax/below'] = (1, lt+lv, below)
    out['G/argmax/rows'] = (1, lt, [int(begin <= i < end) for i in range(len(xs))])
    return out


def normalized(raw, expected):
    out = bytearray(raw); found = set()
    for name, kind, signed, width, log, values, start, width_at in columns(raw):
        reserved = name.startswith('G/embedding/O') or name in ('G/embedding/m', 'G/embedding/mm', 'G/argmax/onehot', 'G/argmax/below', 'G/argmax/rows')
        if not reserved: continue
        assert name in expected and name not in found, name
        w, n, v = expected[name]
        assert (kind, signed, width, log, values) == (2, 0, w, n, v), name
        found.add(name)
        out[start:start+8*len(values)] = bytes(8*len(values))
        out[width_at:width_at+2] = b'\x00\x01'
    assert found == set(expected)
    return bytes(out)


def template(raw):
    return digest(b'stele/v0.1/dev-e2e/plan-template/v1'+u64(len(raw))+raw)


def entry(cqis, model, T, static, templ, relation_bytes, V, d, ee, f0, ms):
    raw = (b'stele-dev-plan-v1'+cqis+model+u32(T)+b'\x05'+static+templ+u64(relation_bytes)+
           struct.pack('<IHhB', V, d, ee, f0)+u32(len(ms))+struct.pack('<'+'H'*len(ms), *ms))
    assert len(raw) == 171+2*V
    return raw


def public(raw):
    r = Reader(raw); assert r.take(19) == b'stele-dev-public-v4'
    start = r.at
    model, scales, prep = r.blob(), r.blob(), r.blob()
    vectors = [(r.take(2), r.blob()) for _ in range(r.number('I'))]
    data = raw[start:r.at]
    roots = []
    for _ in range(r.number('I')): roots.append(r.take(32)); r.blob()
    xs = [r.number('I') for _ in range(r.number('I'))]
    begin, end, has_y = r.number('I'), r.number('I'), r.number('B')
    y = r.number('I') if has_y else None
    assert r.at == len(raw)
    return model, scales, data, vectors, roots, xs, begin, end, y


result = {'spec': 'RFC-0026 A16', 'codec_cases': [], 'negative_cases': [], 'production_pins': []}
# Small request-only relations test encoding/normalization, not a full inference proof.
for name, ee, xs, begin, end, y in [
    ('negative-small', -1, [0,0], 0,2,0),
    ('negative-wide', -1, [1,1], 0,2,2),
    ('negative-prefix', -1, [0,1], 0,1,None),
    ('nonnegative-small', 0, [0,0], 0,2,0),
    ('nonnegative-wide', 0, [1,1], 0,2,2),
    ('saturated', 17, [0,1], 1,2,2),
    ('saturating-product', 1, [2,1], 0,2,0),
]:
    V, d, f0, ms = 3, 2, 0, [1,256,65535]
    expected = requests(V,d,ee,f0,ms,xs,begin,end,y)
    raw = b'stele/v0.1/relation/encoding/v1'+u32(0)+u32(len(expected))
    for label,(width,log,values) in expected.items():
        raw += blob(label.encode())+b'\x02'+u32(len(values))+struct.pack('<'+'q'*len(values),*values)+bytes([0,width,log])
    raw += u32(0)*6
    norm = normalized(raw,expected)
    data = blob(b'MDL')+blob(b'SC')+blob(b'P')+u32(1)+struct.pack('<H',3)+blob(struct.pack('<hh',-1,2))
    roots = u32(1)+bytes([0xab])*32
    static = digest(b'stele/v0.1/dev-e2e/plan-static/v1'+u64(len(data))+data+roots)
    model_id = digest(b'stele/v0.1/dev-e2e/model'+bytes([0x11])*32+roots+u32(1)+struct.pack('<HIhh',3,2,-1,2))
    pub = (b'stele-dev-public-v4'+data+roots+blob(b'')+u32(2)+struct.pack('<II',*xs)+
           u32(begin)+u32(end)+(b'\x00' if y is None else b'\x01'+u32(y)))
    ent = entry(bytes([0x11])*32,model_id,2,static,template(norm),len(norm),V,d,ee,f0,ms)
    result['codec_cases'].append(dict(name=name,tokens=xs,start=begin,end=end,next=y,
        public_hex=pub.hex(),request_columns=expected,relation_hex=raw.hex(),normalized_blake3=digest(norm).hex(),
        template_digest=template(norm).hex(),entry_hex=ent.hex()))
    for label in expected:
        bad = bytearray(raw)
        col = next(c for c in columns(raw) if c[0] == label)
        bad[col[-2]] ^= 1
        try: normalized(bytes(bad),expected)
        except AssertionError: pass
        else: raise AssertionError('missed value mutation '+label)
base = result['codec_cases'][0]
raw = bytes.fromhex(base['relation_hex'])
expected = requests(3,2,-1,0,[1,256,65535],[0,0],0,2,0)
for name, kind, signed, width, log, values, start, width_at in columns(raw):
    for label, offset, value in [('value', start, raw[start]^1), ('width', width_at+1, width+1), ('log_len', width_at+2, log+1)]:
        bad = bytearray(raw); bad[offset] = value
        try: normalized(bytes(bad), expected)
        except AssertionError: pass
        else: raise AssertionError('missed '+label)
        result['negative_cases'].append(dict(name=name+'/'+label,base=base['name'],offset=offset,byte=value,error='RegistryRequestMismatch'))
# Data for the independent wrapper's mandatory precedence tests; not runtime controls.
result['preflight_cases'] = [
    dict(name='short-malformed-relation',base=base['name'],relation_hex='ff',error='RegistryTemplateMismatch'),
    dict(name='same-size-malformed-relation',base=base['name'],offset=0,byte=0,error='StatementMismatch'),
    dict(name='trailing-relation-byte',base=base['name'],append_hex='00',error='RegistryTemplateMismatch'),
]
# Wrong and duplicate names are rejected even when values match.
first = columns(raw)[0]
label = first[0].encode()
for label_case,new in [('relabelled', label[:-1]+b'1'),('noncanonical-suffix',label+b'0')]:
    bad = raw.replace(blob(label),blob(new),1)
    try: normalized(bad,expected)
    except AssertionError: pass
    else: raise AssertionError('missed '+label_case)
    result['negative_cases'].append(dict(name=label_case,base=base['name'],relation_hex=bad.hex(),error='RegistryRequestMismatch'))
first_end = first[-1]+3
count = struct.unpack('<I',raw[35:39])[0]
for label_case,bad in [('missing',raw[:35]+u32(count-1)+raw[first_end:]),
                       ('duplicate',raw[:35]+u32(count+1)+raw[39:first_end]+raw[39:])]:
    try: normalized(bad,expected)
    except AssertionError: pass
    else: raise AssertionError('missed '+label_case)
    result['negative_cases'].append(dict(name=label_case,base=base['name'],relation_hex=bad.hex(),error='RegistryRequestMismatch'))
# Blocked embedding: ld+lv=30 forces lb=0; values are sparse to keep the vector small.
blocked = requests(8193,65535,-1,0,[1]*8193,[8192,1],0,2,0)
assert [i for i,v in enumerate(blocked['G/embedding/O0'][2]) if v] == [8192]
assert [i for i,v in enumerate(blocked['G/embedding/O1'][2]) if v] == [1]
result['blocked_embedding'] = dict(V=8193,d=65535,T=2,exponent=-1,fraction=0,mantissa=1,tokens=[8192,1],
    columns={name:dict(width=w,log_len=n,length=len(values),nonzero=[i for i,v in enumerate(values) if v])
             for name,(w,n,values) in blocked.items() if name.startswith('G/embedding/O')})
assert result['codec_cases'][0]['template_digest'] == result['codec_cases'][1]['template_digest'] == result['codec_cases'][2]['template_digest']
assert result['codec_cases'][0]['entry_hex'] == result['codec_cases'][1]['entry_hex'] == result['codec_cases'][2]['entry_hex']
assert result['codec_cases'][3]['template_digest'] == result['codec_cases'][4]['template_digest'] == result['codec_cases'][5]['template_digest'] == result['codec_cases'][6]['template_digest']
result['declaration_variants'] = []
for name in ['one-layer', 'eight-layer']:
    for branch in ['positive', 'negative']:
        hashes, widths = [], []
        for variant in range(3):
            label = f'{name}-{branch}-{variant}'
            folder = DUMP/label
            meta = json.loads((folder/'request.json').read_text())
            relation = (folder/'relation.bin').read_bytes()
            expected = requests(meta['V'],meta['d'],meta['ee'],meta['f0'],meta['mantissas'],meta['tokens'],meta['start'],meta['end'],meta['next'])
            norm = normalized(relation, expected)
            key = 'G/embedding/'+('m' if branch == 'negative' else 'mm')
            widths.append(expected[key][0]); hashes.append(template(norm).hex())
            result['declaration_variants'].append(dict(name=label,request=meta,relation_blake3=digest(relation).hex(),template_digest=hashes[-1],selected_width=widths[-1]))
        assert hashes[0] == hashes[1] == hashes[2], (name,branch,hashes)
        assert widths[0] != widths[1], (name,branch,widths)
for name in ['one-layer','eight-layer']:
    folder = DUMP/name
    raw = (folder/'public.bin').read_bytes(); relation = (folder/'relation.bin').read_bytes()
    proof = (folder/'proof.bin').read_bytes(); cqis = proof[18:50]
    model_raw, scales_raw, data, vectors, roots, xs,begin,end,y = public(raw)
    model = model_decode(model_raw); scale = scales_decode(model,scales_raw)[0]
    V,d,ee,f0,ms = model.shape.vocabulary,model.shape.width,scale.exponent,model.f0,list(scale.values())
    expected = requests(V,d,ee,f0,ms,xs,begin,end,y)
    norm = normalized(relation,expected)
    R = u32(len(roots))+b''.join(roots)
    static = digest(b'stele/v0.1/dev-e2e/plan-static/v1'+u64(len(data))+data+R)
    model_id = digest(b'stele/v0.1/dev-e2e/model'+cqis+R+u32(len(vectors))+b''.join(o+u32(len(c)//2)+c for o,c in vectors))
    ent = entry(cqis,model_id,len(xs),static,template(norm),len(norm),V,d,ee,f0,ms)
    result['production_pins'].append(dict(name=name,T=len(xs),vocabulary=V,width=d,exponent=ee,fraction=f0,
        public_blake3=digest(raw).hex(),proof_blake3=digest(proof).hex(),relation_blake3=digest(relation).hex(),
        normalized_blake3=digest(norm).hex(),static_digest=static.hex(),template_digest=template(norm).hex(),
        model_identity=model_id.hex(),entry_hex=ent.hex()))
encoded = json.dumps(result,sort_keys=True,separators=(',', ':'))+'\n'
if len(sys.argv) == 4 and sys.argv[3] == '--check':
    assert encoded == Path(__file__).with_name('vectors.json').read_text(), 'A16 vector drift'
    print('A16 reference vectors match')
else:
    print(encoded,end='')
