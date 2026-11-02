# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0023: independent verification of one native public artifact; no producer.

Fresh worker RSS includes startup/runtime/serialization. Timers split actual
standalone imports from the complete closed consumer; no isolated heap claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from time import perf_counter_ns

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'tests/negative-controls/requant'))
from reference import load
from protocol_reference import Protocol, Schema, need


def keys(value, names):
    need(type(value) is dict and set(value) == set(names.split()), 'NativeRequestKeys')


def integer(value, limit):
    need(type(value) is int and 0 <= value < limit, 'NativeRequestInteger')
    return value


def array(value, size):
    need(type(value) is list and len(value) == size, 'NativeRequestShape')
    return value


def raw_hex(value, size=None):
    need(type(value) is str and len(value) % 2 == 0 and all(c in '0123456789abcdef' for c in value), 'NativeRequestHex')
    raw = bytes.fromhex(value)
    need(size is None or len(raw) == size, 'NativeRequestShape')
    return raw


def unique(pairs):
    need(len(pairs) == len(dict(pairs)), 'NativeRequestDuplicateKey')
    return dict(pairs)


def usage(observation):
    need(observation['outcome'] == 'success' and len(observation['created_transcripts']) == 1, 'ImportObservation')
    return dict(transcript=observation['created_transcripts'][0], non_transcript=observation['non_transcript'])


def verify_native(path):
    need(sys.version_info[:2] == (3,12) and not sys.flags.optimize, 'Runtime')
    with load(ROOT) as ref:
        start = perf_counter_ns()
        raw = Path(path).read_bytes()
        request = json.loads(raw, object_pairs_hook=unique)
        keys(request, 'degree stage n parameters repetitions advice_blowup point value public_hex input proof_hex following_hex')
        d = integer(request['degree'], 9)
        need(d in (4,8), 'NativeRequestField')
        n, stage = integer(request['n'], 1 << 30), integer(request['stage'], 1 << 20)
        keys(request['parameters'], 'mantissa shift bits')
        params = request['parameters']
        for name in params: integer(params[name], 1 << 32)
        schema = Schema(ref, params['mantissa'], params['shift'], params['bits'], n, stage)
        r = integer(request['repetitions'], 3)
        need(r in (1,2), 'Parameters')
        blowup = integer(request['advice_blowup'], 3)
        def field(v): return tuple(integer(x, ref.sc.P) for x in array(v, d))
        point = [field(v) for v in array(request['point'], schema.m)]
        value = field(request['value'])
        public = raw_hex(request['public_hex'])
        need(0 < len(public) <= 1 << 20, 'NativeRequestPublic')
        info = request['input']
        keys(info, 'id blowup root_hex source_hex certificate_hex')
        source = ref.pcs.Source(d, integer(info['id'], 1 << 64), 2, schema.m,
                                integer(info['blowup'], 3), raw_hex(info['root_hex'], 32))
        need(source.bytes() == raw_hex(info['source_hex'], 105), 'NativeRequestSource')
        packet = dict(source=source, certificate=raw_hex(info['certificate_hex']))
        wire = raw_hex(request['proof_hex'])
        need(len(wire) <= 32_000_000, 'ResourceLimit')
        following = ref.pcs.fields(raw_hex(request['following_hex'], 12*d), d)
        next_proof = dict(rounds=[following[:2]], final=following[2:])
        times = dict(decode_and_schema=perf_counter_ns()-start)
        tick = perf_counter_ns()
        protocol = Protocol(ref, schema, d, r, packet, point, value, public, blowup)
        setup_ns = perf_counter_ns()-tick
        input_import = protocol.observations[0]
        times['input_import'] = input_import['elapsed_ns']
        times['expected_descriptor'] = setup_ns-times['input_import']
        tick = perf_counter_ns()
        records, transcript = protocol.verify(wire)
        closed_ns = perf_counter_ns()-tick
        advice_import = next(o for o in protocol.observations if o['scope'] == 'advice-import-verifier')
        times['advice_import'] = advice_import['elapsed_ns']
        times['multiplicity_imports'] = sum(sum(o['registration_ns']) for o in records['lookups'])
        times['closed_relation'] = closed_ns-times['advice_import']-times['multiplicity_imports']
        local = ref.o.hashes()
        outer = [o for o in protocol.observations if o['scope'] == 'outer-advice-packet-identity' or o['scope'].startswith('verify-A9-')]
        need(len(outer) == 4, 'OuterObservation')
        for o in outer + [o['usage'] for o in records['lookups']]:
            local = {k:v+o['non_transcript'][k] for k,v in local.items()}
        result = dict(imports=dict(input=usage(input_import), advice=usage(advice_import),
            multiplicities=[o['registrations'] for o in records['lookups']]),
            usage=dict(transcript=transcript.usage.copy(), non_transcript=local),
            record=dict(lookups=[o['record'] for o in records['lookups']],
                zero={k:records['zero'][k] for k in ('claims','sc')}, output=records['output'],
                groups=[dict(point=g['point'], claims=list(zip(g['rows'],g['ids'],g['claims'])), opening=g['opening_record']) for g in records['groups']],
                rlc=[{k:r[k] for k in ('stage','phase','field_degree','count','numerator','weights')} for r in records['rlc']]))
        tick = perf_counter_ns()
        instance = dict(id=schema.S+(1 << 29), m=1, ids=[schema.S+(1 << 29)+1],
            terms=[(ref.sc.scalar(1,d),[0])], sum=ref.sc.scalar(3,d))
        record = ref.sc.verify_public(transcript, instance, next_proof, [[ref.sc.scalar(1,d),ref.sc.scalar(2,d)]])
        # The native public consumer returns only the closed point/accounting.
        result['continuation'] = dict(record={k:record[k] for k in ('point','sc')}, usage=transcript.usage.copy())
        result['continuation']['probe'] = ref.sc.encode(transcript.field(ref.pcs.CHALLENGE)).hex()
        diagnostic = transcript.usage.copy()
        times['continuation'] = perf_counter_ns()-tick
        tick = perf_counter_ns()
        del protocol, records, transcript, next_proof, packet, wire
        ref.o.CREATED.clear()
        times['cleanup'] = perf_counter_ns()-tick
        total = perf_counter_ns()-start
        sources = {}
        for module in list(sys.modules.values()):
            filename = getattr(module, '__file__', None)
            if filename and Path(filename).resolve().is_relative_to(ROOT):
                filename=Path(filename).resolve()
                sources[str(filename.relative_to(ROOT))]=hashlib.sha256(filename.read_bytes()).hexdigest()
        for name in ('tests/negative-controls/requant_corpus.py.lock',
                     'tests/negative-controls/requant/reference-provenance.json'):
            sources[name]=hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
        return dict(verification=result, stages_ns=times, total_ns=total,
            remainder_ns=total-sum(times.values()), diagnostic_probe_usage=diagnostic,
            request_sha256=hashlib.sha256(raw).hexdigest(), sources=sources,
            runtime=dict(version=sys.version.split()[0], executable=sys.executable, implementation=sys.implementation.name, optimization=sys.flags.optimize))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-native', required=True, type=Path)
    print(json.dumps(verify_native(parser.parse_args().verify_native), sort_keys=True, separators=(',',':')))
