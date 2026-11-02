"""RFC-0024 §6 independent following-A1 mutations from actual transcript replay.

Only the following final changes. The complete accepted operation is fixed.
The replay is an untrusted message history, not another accepting verifier.
"""
from copy import deepcopy
import struct
from integer_linear_reference import LINEAR, decode_request, following_instance, need
from protocol_reference import CONSTRAINTS, CLAIMS


def requests(ref, request):
    """Record a genuine verification, then omit exactly one absorb per replay."""
    base = ref.Transcript

    class Observed(base):
        def __init__(self, public, degree):
            self.events = []
            super().__init__(public, degree)

        def absorb(self, label, payload):
            super().absorb(label, payload)
            self.events.append(('absorb', label, payload))

        def challenge(self, label=ref.pcs.CHALLENGE):
            if not self.in_column:
                self.events.append(('challenge', label))
            return super().challenge(label)

        def column(self, label, size):
            self.events.append(('column', label, size))
            return super().column(label, size)

    ref.Transcript = Observed
    try:
        operation, wire, following = decode_request(ref, request)
        _, observed = operation.verify(wire)
    finally:
        ref.Transcript = base
    need(type(observed) is Observed, 'ObservedOuterTranscript')
    instance = following_instance(operation)
    tables = [[ref.sc.scalar(1, operation.d), ref.sc.scalar(2, operation.d)]]

    def replay(omit=None):
        transcript = base(operation.public, operation.d)
        for index, (method, *args) in enumerate(observed.events):
            if index != omit:
                getattr(transcript, method)(*args)
        return transcript

    honest = replay()
    need(honest.state == observed.state and honest.usage == observed.usage
         and honest.draw_trace == observed.draw_trace, 'ExactUnmodifiedHistory')
    generated, _ = ref.sc.prove(honest, instance, tables)
    need(generated == following, 'ActualFollowingProducer')
    omissions, opening = {}, None
    for index, event in enumerate(observed.events):
        if event[0] != 'absorb':
            continue
        _, label, payload = event
        if label in (LINEAR, CONSTRAINTS):
            name = 'statement' if label == LINEAR else 'constraints'
        elif label == CLAIMS:
            need(payload[4] in (0, 1, 2), 'GroupPhase')
            name = f'group-{payload[4]}'
        elif label == ref.pcs.OPEN:
            opening = struct.unpack_from('<Q', payload)[0]
            continue
        elif label == ref.pcs.OPEN_COLUMNS and opening in (101, 102):
            name = f'original-{opening}-responses'
        else:
            continue
        need(name not in omissions, 'UniqueOmittedFrame')
        omissions[name] = index
    need(list(omissions) == ['statement', 'constraints', 'group-0', 'group-1', 'group-2',
                            'original-101-responses', 'original-102-responses'], 'FrameInventory')
    yield dict(name='honest', request=request)
    for name, index in omissions.items():
        wrong, _ = ref.sc.prove(replay(index), instance, tables)
        need(wrong['rounds'] == following['rounds'] and len(wrong['final']) == 1
             and wrong['final'] != following['final'], 'OneFollowingFinal')
        changed = deepcopy(request)
        width = 4*operation.d
        original = bytes.fromhex(request['following_hex'])
        final = ref.sc.encode(wrong['final'][0])
        changed['following_hex'] = (original[:-width]+final).hex()
        need(bytes.fromhex(changed['following_hex'])[:-width] == original[:-width], 'UnchangedRounds')
        need({k: v for k, v in changed.items() if k != 'following_hex'}
             == {k: v for k, v in request.items() if k != 'following_hex'}, 'FixedOperation')
        yield dict(name=name, request=changed)
