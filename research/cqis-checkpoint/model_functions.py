"""Q26 / RFC-0021 §4, Draft RFC-0004 A3/A10: model-selected function manifest."""
import hashlib
import model_config as c

fn=c.fn
TAG=b'stele/research/q26/model-functions/v1\0'
CAPACITY=1<<20


def selection(p):
    c.require(type(p) is c.Config,'Config'); refs=[]
    def norm(n): return fn.Representation(fn.Function('rmsnorm_q',1,c.norm_bytes(n)),3,b'')
    for i,b in enumerate(p.blocks):
        prefix='layer.'+str(i)+'.'
        refs.extend(((prefix+'norm1',norm(b.norm1)),(prefix+'attention_exp',b.projection.representation),
                     (prefix+'norm2',norm(b.norm2)),(prefix+'silu',fn.Representation(b.silu,0,b''))))
    refs.append(('final_norm',norm(p.final_norm)))
    c.require(len(refs)==4*len(p.blocks)+1<=513 and len({name for name,_ in refs})==len(refs),'Roles')
    chosen={}
    for _,r in refs:
        identity=fn.function_id(r.function)
        c.require(identity not in chosen or chosen[identity]==r,'Representation'); chosen[identity]=r
    selected=tuple(chosen[k] for k in sorted(chosen))
    c.require(selected==c.representations(p),'Roles')
    _,components=fn.closure(selected); components=tuple(components)
    c.require(len(components)<=4*len(p.blocks)+1 and len(selected)<=513,'Capacity')
    for d in components:
        rows,padded,columns=fn.table.shape(d)
        c.require(1<=rows<=padded<=65536 and columns==2,'Capacity')
    return tuple(refs),selected,components


def _derive(expected_config,config_bytes):
    c.hash32(expected_config); p=c.decode(config_bytes)
    c.require(c.identity(p)==expected_config,'Identity')
    refs,selected,components=selection(p)
    # Definition-derived data digests only; no supplied table/hash callback.
    manifest=fn.encode_manifest(selected)
    chunks=[TAG+expected_config+len(refs).to_bytes(2,'little')]; size=len(chunks[0])
    for name,r in refs:
        c.require(name.isascii() and 1<=len(name)<=64,'Role'); name=name.encode('ascii')
        entry=len(name).to_bytes(2,'little')+name+fn.function_id(r.function)+fn.representation_id(r)
        size+=len(entry); c.require(size<=CAPACITY-4,'Capacity'); chunks.append(entry)
    c.require(len(manifest)<=CAPACITY-size-4,'Capacity')
    chunks.extend((len(manifest).to_bytes(4,'little'),manifest)); raw=b''.join(chunks)
    return refs,selected,components,manifest,raw


def encode(expected_config,config_bytes):
    return _derive(expected_config,config_bytes)[-1]


def validate(expected_config,config_bytes,raw):
    c.require(type(raw) is bytes,'FunctionSet'); c.require(len(raw)<=CAPACITY,'Capacity')
    c.require(raw==encode(expected_config,config_bytes),'FunctionSet')


def evidence(expected_config,config_bytes):
    """Correctness evidence; no table-root, artifact or complete proof-plan identity."""
    refs,selected,components,manifest,raw=_derive(expected_config,config_bytes)
    return dict(function_roles=len(refs),function_count=len(selected),function_components=len(components),
        function_manifest_bytes=len(manifest),function_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        model_functions_bytes=len(raw),model_functions_sha256=hashlib.sha256(raw).hexdigest())
