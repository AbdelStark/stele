# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0012 A1 candidate byte oracle; research only, no NC catalog credit."""
import collections
import itertools
import json
import pathlib
import struct
import sys
from blake3 import blake3

P = 2**31 - 1
INITIAL = b"stele/v0.1/transcript/init"
PUBLIC = b"stele/v0.1/public"
INSTANCE = b"stele/v0.1/sumcheck/instance"
ROUND = b"stele/v0.1/sumcheck/round"
FINAL = b"stele/v0.1/sumcheck/final"
CHALLENGE = b"stele/v0.1/sumcheck/challenge"
LABELS = (PUBLIC, INSTANCE, ROUND, FINAL, CHALLENGE)


def registry(labels):
    if len(set(labels)) != len(labels):
        raise ValueError("DuplicateLabel")
    if any(not 1 <= len(v) <= 255 or not v.isascii() or not v.startswith(b"stele/v0.1/") for v in labels):
        raise ValueError("InvalidLabel")


def frame(state, tag, label, payload):
    if len(state) != 32 or tag not in (0, 1, 2) or label not in LABELS:
        raise ValueError("InvalidFrame")
    return state + bytes([tag]) + struct.pack("<I", len(label)) + label + struct.pack("<Q", len(payload)) + payload


def decode_frame(data):
    if len(data) < 45:
        raise ValueError("InvalidFrame")
    n = struct.unpack_from("<I", data, 33)[0]
    if len(data) < 45 + n:
        raise ValueError("InvalidFrame")
    size = struct.unpack_from("<Q", data, 37+n)[0]
    if len(data) != 45+n+size:
        raise ValueError("InvalidFrame")
    state, tag, label, payload = data[:32], data[32], data[37:37+n], data[45+n:]
    if frame(state, tag, label, payload) != data:
        raise ValueError("InvalidFrame")
    return state, tag, label, payload


def sample(raw, degree):
    if degree not in (4, 8) or len(raw) != 256:
        raise ValueError("InvalidSamplingInput")
    limbs = []
    for consumed, (word,) in enumerate(struct.iter_unpack("<I", raw), 1):
        limb = word & P
        if limb < P:
            limbs.append(limb)
        if len(limbs) == degree:
            return struct.pack("<"+"I"*degree, *limbs), consumed
    raise ValueError("SamplingExhausted")


class Transcript:
    def __init__(self, public, degree):
        registry(LABELS)
        if not public or degree not in (4, 8):
            raise ValueError("InvalidTranscript")
        self.degree = degree
        self.state = blake3(frame(blake3(INITIAL).digest(), 0, PUBLIC, public)).digest()

    def absorb(self, label, message):
        if label not in (INSTANCE, ROUND, FINAL):
            raise ValueError("InvalidAbsorbLabel")
        self.state = blake3(frame(self.state, 0, label, message)).digest()

    def challenge(self):
        old = self.state
        request = frame(old, 1, CHALLENGE, bytes([self.degree]))
        value, consumed = sample(blake3(request).digest(length=256), self.degree)
        payload = bytes([self.degree]) + struct.pack("<I", consumed) + value
        self.state = blake3(frame(old, 2, CHALLENGE, payload)).digest()
        return value, consumed


def rejects(function, reason):
    try:
        function()
    except ValueError as error:
        assert str(error) == reason, (error, reason)
    else:
        raise AssertionError("accepted invalid input")


def checks():
    registry(LABELS)
    assert blake3(b"").hexdigest() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    changed = list(LABELS); changed[-1] = changed[2]
    rejects(lambda: registry(changed), "DuplicateLabel")
    rejects(lambda: registry((b"stele/v0.1/\xff",)), "InvalidLabel")
    # Exhaustive small-prime analogue: exactly two raw preimages per accepted limb.
    for bits in range(2, 9):
        mask = (1 << bits)-1
        counts = collections.Counter(w & mask for w in range(1 << (bits+1)) if (w & mask) < mask)
        assert set(counts) == set(range(mask)) and set(counts.values()) == {2}
    pairs = collections.Counter()
    for words in itertools.product(range(8), repeat=3):
        accepted = [w & 3 for w in words if (w & 3) < 3]
        if len(accepted) >= 2:
            pairs[tuple(accepted[:2])] += 1
    assert set(pairs) == set(itertools.product(range(3), repeat=2))
    assert set(pairs.values()) == {48}  # Conditioning on success within the cap preserves uniformity.
    # Exercise both rejected words, both endpoints and high-bit aliases without needing a rare hash event.
    words = [P, 0xffffffff, 0, 0x80000000, P-1, 0xfffffffe, 1, 2, 3, 4] + [5]*54
    encoded, consumed = sample(struct.pack("<64I", *words), 8)
    assert consumed == 10 and struct.unpack("<8I", encoded) == (0, 0, P-1, P-1, 1, 2, 3, 4)
    rejects(lambda: sample(struct.pack("<64I", *([P]*64)), 8), "SamplingExhausted")
    assert sample(struct.pack("<64I", *([P]*56 + list(range(8)))), 8)[1] == 64
    rejects(lambda: sample(struct.pack("<64I", *([P]*57 + list(range(7)))), 8), "SamplingExhausted")
    seen = set()
    for tag, label, payload in itertools.product(range(3), LABELS, (b"", b"a", b"bc", b"a\x00bc")):
        encoded = frame(bytes(32), tag, label, payload)
        assert encoded not in seen and decode_frame(encoded) == (bytes(32), tag, label, payload)
        seen.add(encoded)
        rejects(lambda: decode_frame(encoded+b"\x00"), "InvalidFrame")
    public = b"synthetic public input; not a proof"
    for degree in (4, 8):
        honest = Transcript(public, degree); honest.absorb(ROUND, b"round message")
        first = honest.challenge()[0]; second = honest.challenge()[0]
        assert first != second
        early = Transcript(public, degree); assert early.challenge()[0] != first
        honest.absorb(FINAL, b"final claims"); expected = honest.challenge()[0]
        omitted = Transcript(public, degree); omitted.absorb(ROUND, b"round message")
        omitted.challenge(); omitted.challenge()
        assert omitted.challenge()[0] != expected
        changed = Transcript(public, degree); changed.absorb(ROUND, b"round messagf")
        assert changed.challenge()[0] != first
    assert Transcript(public, 4).challenge()[0] != Transcript(public, 8).challenge()[0][:16]


def vectors():
    result = []
    for degree in (4, 8):
        public = b"synthetic public input; not a proof"
        t = Transcript(public, degree)
        events = [{"public_hex": public.hex(), "state_hex": t.state.hex()}]
        for label, message in [(INSTANCE, bytes(range(16))), (ROUND, bytes(range(64))),
                               (FINAL, b"final claims"), (ROUND, b"second round")]:
            t.absorb(label, message)
            events.append({"label": label.decode(), "message_hex": message.hex(), "state_hex": t.state.hex()})
            value, consumed = t.challenge()
            events.append({"challenge_hex": value.hex(), "consumed_words": consumed, "state_hex": t.state.hex()})
        result.append({"degree": degree, "events": events})
    return {"spec": "RFC-0012-A1-candidate", "hash_backend": "blake3-py 1.0.11 (official Rust backend)", "vectors": result}


if __name__ == "__main__":
    checks()
    path = pathlib.Path(__file__).with_name("candidate-vectors.json")
    data = vectors()
    if sys.argv[1:] == ["--write-candidate"]:
        with path.open("x") as file:
            json.dump(data, file, indent=2); file.write("\n")
    else:
        assert not sys.argv[1:], "unknown arguments"
        assert json.loads(path.read_text()) == data
    print("candidate framing, rejection, label, ratchet and message-sensitivity checks passed; no protocol coverage")
