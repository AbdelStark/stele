"""Draft RFC-0025 preparation/execution and encoding §6 identity joins; no proof API."""
from dataclasses import dataclass
from io import BytesIO

from blake3 import blake3

import bound_collection
from model_codec import encode as encode_model
import model_execution
import source_architecture
import source_codec
import source_conversion

IDENTITY=b'stele/v0.1/cqis/identity'


@dataclass(frozen=True)
class Prepared:
    source_config: bytes
    conversion: source_conversion.Conversion
    execution: model_execution.Data


def prepare(model,mapping,layout,source,assets,files):
    snapshot=source_codec._snapshot(files)
    source_codec.encode_assets(assets); names={f.name for f in source_codec._asset_files(assets)}
    if not names<=set(snapshot): raise ValueError('FileSet')
    config=source_architecture.binding(model,mapping,layout,assets,{name:snapshot[name] for name in names})
    output=BytesIO()
    converted=source_conversion.convert(model,mapping,source,assets,snapshot,output)
    # Validate the immutable stored bytes, not just the converter's emitted-byte digest.
    execution=model_execution.load(model,mapping,converted.scales,output.getvalue(),converted.digest)
    return Prepared(config,converted,execution)


def identity_frame(model,scales,registry,bounds):
    raw=encode_model(model)
    # Complete collection validation also validates Scales and regenerates Registry data.
    bound_collection.validate(model,scales,registry,bounds)
    return IDENTITY+b''.join(blake3(value).digest() for value in (raw,scales,registry,bounds))


def identity(model,scales,registry,bounds):
    return blake3(identity_frame(model,scales,registry,bounds)).digest()


def verify_identity(model,scales,registry,bounds,raw):
    if type(raw) is not bytes or len(raw)!=len(IDENTITY)+128: raise ValueError('Identity')
    if raw!=identity_frame(model,scales,registry,bounds): raise ValueError('Identity')
