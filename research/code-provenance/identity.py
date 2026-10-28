"""RFC-0010 A1 candidate identity/registry boundary; no PCS admission API."""
import tomllib
from fractions import Fraction
from sampler import parse_manifest, materialize, all_seeds_bound, EVENTS
from recursive import geometry, encode_row, circle, sc

CIRCLE = b'stele/circle-m31/v1'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def catalog():
    return {'version': 1, 'code': [
        dict(id='circle-m31/v1', proven=False,
             distance_evidence='rfc-0010-a2/root-bound-v1', assumption='none',
             max_log_codeword=30, log_blowups=[1, 2]),
        dict(id='expander-m31/v2', proven=False,
             distance_evidence='rfc-0010-a1/finite-v2', assumption='blake3-random-oracle',
             setup_evidence='rfc-0012-a7/2^256-all-seeds-v2', exponents=list(range(3, 16)),
             seed_bits=256, setup_loss_numerator=EVENTS, setup_loss_denominator_bits=160),
    ]}


def validate_catalog(raw):
    require(type(raw) is bytes and len(raw) <= 4096, 'InvalidRegistry')
    try:
        supplied = tomllib.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise ValueError('InvalidRegistry') from None

    def equal(a, b):
        if type(a) is not type(b):
            return False
        if type(a) is dict:
            return a.keys() == b.keys() and all(equal(a[key], b[key]) for key in a)
        if type(a) is list:
            return len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b))
        return a == b

    require(equal(supplied, catalog()), 'InvalidRegistry')


def parameters(raw_id, field):
    require(type(raw_id) is bytes, 'InvalidCodeId')
    if len(raw_id) == 21 and raw_id[:19] == CIRCLE:
        m, blowup = raw_id[-2:]
        require(blowup in (1, 2) and m+blowup <= 30, 'InvalidCodeId')
        n, total = 1 << m, 1 << (m+blowup)
        result = dict(family='circle-m31/v1', message_len=n, codeword_len=total,
                      distance=total if n == 1 else total-n, setup_loss=Fraction(0),
                      edge_count=0, setup_bytes=0)
    else:
        try:
            _, j = parse_manifest(raw_id)
        except ValueError:
            raise ValueError('InvalidCodeId') from None
        n = 4**j
        edges = sum(rows*degree for k in range(4, j+1) for rows, _, degree in geometry(k))
        result = dict(family='expander-m31/v2', message_len=n, codeword_len=2*n,
                      distance=64 if j == 3 else n//25+1,
                      setup_loss=Fraction(0) if j == 3 else all_seeds_bound(),
                      edge_count=edges, setup_bytes=43+8*edges)
    require(type(field) is int and field in (1, 4, 8), 'FieldMismatch')
    return dict(result, field_degree=field)


def validate_row(info, row):
    require(type(row) in (list, tuple) and len(row) == info['message_len'], 'RowShape')
    require(all(type(v) is tuple and len(v) == info['field_degree']
                and all(type(x) is int and 0 <= x < sc.P for x in v) for v in row), 'RowShape')


def encode(raw_id, field, row):
    info = parameters(raw_id, field)
    validate_row(info, row)
    if info['family'] == 'circle-m31/v1':
        return list(zip(*(circle.encode(list(values), raw_id[-1]) for values in zip(*row))))
    setup, _ = materialize(raw_id)
    return encode_row(setup, row)[0]


def eval_row(raw_id, field, row, columns):
    info = parameters(raw_id, field)
    validate_row(info, row)
    require(type(columns) in (list, tuple) and all(type(c) is int and 0 <= c < info['codeword_len']
                                                for c in columns), 'Column')
    if not columns:
        return []
    word = encode(raw_id, field, row)
    return [word[c] for c in columns]
