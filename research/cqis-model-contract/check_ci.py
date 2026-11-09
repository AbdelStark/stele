# /// script
# requires-python = "==3.12.*"
# dependencies = ["blake3==1.0.11", "python-flint==0.9.0", "safetensors==0.6.2"]
# ///
"""RFC-0025 regression checks; full qualification receipts remain separate.

Reuse independent exact oracles without invoking any historical campaign main.
These bounded cases confer no named-model, native proof or performance credit.
"""
from dataclasses import replace
import json
from random import Random

import check_bound_collection as bounds
import check_decoding_execution as decoding
import check_grouped_rows as grouped
import check_model_execution as execution
import check_passport_composition as passport
import check_preparation_execution as preparation
import check_public_input as public
import check_wide_residual as wide
import synthetic_e2e


def bound_cases():
    rng = Random(26960)
    schemas = set()
    for family in range(2):
        shape = bounds.Shape(family, 1, 4, 2, 2 if not family else 1, 2,
                             16 if not family else 7, 5, 3)
        for mode in range(3):
            model = bounds.fixture(rng, family, shape, mode)
            # Every mode includes the complete sampled-decoding schemas.
            exp = replace(model.blocks[0].exp, n=shape.vocabulary)
            model = replace(model, decoding=bounds.Sampled(1, 1, 3, 4, exp))
            scales = bounds.make_scales(rng, model)
            sr = bounds.c.scales_codec.encode(model, scales)
            rr = bounds.c.registry_codec.encode(model)
            assert sr == bounds.scales_oracle(model, scales)
            assert rr == bounds.registry_oracle(model)
            records = bounds.expected_records(model, scales)
            assert records == bounds.c._records(model, scales)
            schemas.update(type(value).__name__ for _, _, value in records)
            raw = b''.join(bounds.c.iterencode(model, sr, rr))
            assert raw == b''.join(bounds.framing(model, sr, rr, records, independent=True))
            bounds.c.validate(model, sr, rr, raw)
            for at in (0, len(raw)//2, len(raw)-1):
                changed = raw[:at]+bytes((raw[at] ^ 1,))+raw[at+1:]
                bounds.rejects(lambda: bounds.c.validate(model, sr, rr, changed), 'Encoding')
    assert len(schemas) == 19
    return dict(models=6, schemas=sorted(schemas))


def source_cases():
    rng = Random(26961)
    outcomes = {}
    for layout in range(3):
        for dtype in range(1, 5):
            result, values, tag = preparation.check(rng, layout, dtype, 1+dtype % 3)
            outcomes[tag] = outcomes.get(tag, 0)+1
            if dtype == 1:
                preparation.controls(values, layout)
                preparation.identity_case(values[0], result.conversion.scales)
    return dict(packages=12, outcomes=outcomes)


def decoding_cases():
    rng = Random(26962)
    counts = {'accept': 0, 'reject': 0}
    for family in range(2):
        for mode in range(-1, 3):
            for _ in range(8):
                m, r, p, prefix, logits, seed = decoding.fixture(rng, family, mode)
                raw = decoding.c.policy(m, r)
                assert raw == decoding.policy_oracle(m, r)
                decoding.c.verify_policy(m, r, raw)
                decoding.c.validate_seed(m, r, seed)
                try:
                    expected = decoding.oracle(m, r, prefix, logits, seed)
                except ValueError as error:
                    assert str(error) == 'ExpDomain'
                    decoding.rejects(lambda: decoding.c.choose(m, r, p, prefix, logits, seed), 'ExpDomain')
                    counts['reject'] += 1
                else:
                    assert decoding.c.choose(m, r, p, prefix, logits, seed) == expected
                    counts['accept'] += 1
    return dict(cases=64, outcomes=counts, boundaries=decoding.boundaries())


def execution_cases():
    # Exact scalar/oracle comparisons include tails, cache scope, absolute block
    # boundaries and a failed later head that must not expose partial state.
    rng = Random(26964)
    accepted = [0, 0]
    for family in range(2):
        for _ in range(8):
            case = execution.fixture(rng, family, layers=1)
            model, mapping, scales, raw, arrays = case
            tokens = (0, 1)
            try:
                expected = execution.reference(model, arrays, tokens)
            except ValueError as error:
                assert str(error) in ('Range', 'RowRange', 'ExpDomain')
                data = execution.c.load(model, mapping, scales, raw, execution.blake3(raw).digest())
                execution.rejects(lambda: execution.c.full(data, tokens), str(error))
            else:
                execution.compare(*case, tokens, expected)
                accepted[family] += 1
    assert all(accepted)
    return dict(accepted_families=accepted, boundaries=execution.boundaries(), blocks=execution.block_boundary(),
                atomic=execution.atomic_failure())


def identity_cases():
    models = public.templates(Random(26963))
    return dict(public_controls=public.boundaries(models),
                numerical_joins=public.numerical_joins(),
                passport_controls=passport.boundaries(), source_joins=passport.source_joins())


def wide_cases():
    return wide.report()


def grouped_cases():
    return grouped.report()


def synthetic_cases():
    """RFC-0026 E16-10: the committed synthetic end-to-end fixture regenerates exactly."""
    return synthetic_e2e.check()


def main():
    if not __debug__:
        raise RuntimeError('oracle assertions must be enabled')
    for check in (bound_cases, source_cases, decoding_cases, execution_cases, identity_cases, wide_cases, grouped_cases,
                  synthetic_cases):
        print(json.dumps(dict(check=check.__name__, status='running')), flush=True)
        result = check()
        print(json.dumps(dict(check=check.__name__, status='passed', result=result), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
