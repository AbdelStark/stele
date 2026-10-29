"""Q26 / Draft RFC-0004 A3/A10: closed scoped collection, not a proof plan."""
import hashlib
import model_config as c
import model_scaled_bounds as scaled
import model_row_bounds as row
import model_rotary_bounds as rotary
import model_residual_bounds as residual
import model_greedy_bounds as greedy
import model_attention_sum_bounds as total
import model_attention_normalization_bounds as normalization
import model_attention_block_bounds as block
import model_attention_score_bounds as score
import model_attention_max_bounds as maximum
import model_gated_product_bounds as gated
import model_norm_bounds as norm

TAG=b'stele/research/q26/model-bounds/v1\0'
CAPACITY=1<<25
FAMILIES=(scaled,row,rotary,residual,greedy,total,normalization,block,score,maximum,gated,norm)


def encode(expected_config,config_bytes,expected_artifact,artifact_bytes):
    """Expected hashes are caller-owned; supplied collection bytes select no authority."""
    model=c.load(expected_config,config_bytes,expected_artifact,artifact_bytes)
    records=tuple((i,name,raw) for i,module in enumerate(FAMILIES,1)
                  for name,_,raw in module.records(model))
    count=25*len(model.blocks)+sum(b.attention.attention.accumulation=='block1024' for b in model.blocks)+5
    c.require(len(records)==count<=3333 and len({(i,name) for i,name,_ in records})==count,'Roles')
    chunks=[TAG+expected_config+expected_artifact+count.to_bytes(4,'little')]; size=len(chunks[0])
    for family,name,raw in records:
        c.require(type(name) is str and name.isascii() and 1<=len(name)<=64,'Role')
        c.require(type(raw) is bytes and len(raw)<=8192,'Capacity'); name=name.encode('ascii')
        entry=bytes([family])+len(name).to_bytes(2,'little')+name+len(raw).to_bytes(4,'little')+raw
        size+=len(entry); c.require(size<=CAPACITY,'Capacity'); chunks.append(entry)
    return b''.join(chunks)


def validate(expected_config,config_bytes,expected_artifact,artifact_bytes,raw):
    c.require(type(raw) is bytes,'BoundSet'); c.require(len(raw)<=CAPACITY,'Capacity')
    expected=encode(expected_config,config_bytes,expected_artifact,artifact_bytes)
    c.require(raw==expected,'BoundSet')


def evidence(expected_config,config_bytes,expected_artifact,artifact_bytes):
    """Correctness checksum; not complete cqis_id, registry or source authentication."""
    raw=encode(expected_config,config_bytes,expected_artifact,artifact_bytes)
    config=c.decode(config_bytes)
    count=25*len(config.blocks)+sum(b.projection.attention.accumulation=='block1024' for b in config.blocks)+5
    return dict(bound_set_records=count,bound_set_bytes=len(raw),bound_set_sha256=hashlib.sha256(raw).hexdigest())
