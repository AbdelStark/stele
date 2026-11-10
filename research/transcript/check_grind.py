# /// script
# requires-python = ">=3.12"
# dependencies = ["blake3==1.0.11"]
# ///
"""RFC-0012 A17 grinding: independent byte oracle for the stele-hash KAT; no NC credit.

Re-implements the A1 transcript (frame, absorb, challenge) and the A17 nonce from the RFC
text, separately from check_transcript.py (whose digest is pinned by frozen evidence).
"""
import itertools
import json
import pathlib
import struct
import sys
from blake3 import blake3

P = 2**31 - 1
INITIAL = b"stele/v0.1/transcript/init"
PUBLIC = b"stele/v0.1/public"
ROUND = b"stele/v0.1/sumcheck/round"
CHALLENGE = b"stele/v0.1/sumcheck/challenge"
GRIND = b"stele/v0.1/grind"
MAX_GRIND_BITS = 32


def frame(state, tag, label, payload):
    assert len(state) == 32 and tag in (0, 1, 2, 3)
    return state + bytes([tag]) + struct.pack("<I", len(label)) + label + struct.pack("<Q", len(payload)) + payload


class Transcript:
    def __init__(self, public, degree):
        self.degree = degree
        self.state = blake3(frame(blake3(INITIAL).digest(), 0, PUBLIC, public)).digest()

    def absorb(self, label, message):
        self.state = blake3(frame(self.state, 0, label, message)).digest()

    def challenge(self):
        raw = blake3(frame(self.state, 1, CHALLENGE, bytes([self.degree]))).digest(length=256)
        limbs = []
        for consumed, (word,) in enumerate(struct.iter_unpack("<I", raw), 1):
            if (word & P) < P:
                limbs.append(word & P)
            if len(limbs) == self.degree:
                value = struct.pack("<" + "I" * self.degree, *limbs)
                payload = bytes([self.degree]) + struct.pack("<I", consumed) + value
                self.state = blake3(frame(self.state, 2, CHALLENGE, payload)).digest()
                return value
        raise ValueError("SamplingExhausted")

    def pow(self, bits, nonce):
        if not 1 <= bits <= MAX_GRIND_BITS:
            raise ValueError("InvalidGrindBits")
        payload = bytes([bits]) + struct.pack("<Q", nonce)
        word = struct.unpack("<Q", blake3(frame(self.state, 3, GRIND, payload)).digest()[:8])[0]
        return word % (1 << bits) == 0

    def grind(self, bits):
        nonce = next(n for n in itertools.count() if self.pow(bits, n))
        self.absorb(GRIND, bytes([bits]) + struct.pack("<Q", nonce))
        return nonce

    def verify_grind(self, bits, nonce):
        if not self.pow(bits, nonce):
            raise ValueError("GrindMismatch")
        self.absorb(GRIND, bytes([bits]) + struct.pack("<Q", nonce))


def start(degree):
    t = Transcript(b"synthetic public input; not a proof", degree)
    t.absorb(ROUND, b"grinding round")
    return t


def vectors():
    result = []
    for degree in (4, 8):
        t = start(degree)
        events = [{"state_hex": t.state.hex()}]
        for bits in (1, 8, 12):
            nonce = t.grind(bits)
            events.append({"bits": bits, "nonce": nonce, "challenge_hex": t.challenge().hex(),
                           "state_hex": t.state.hex()})
        result.append({"degree": degree, "events": events})
    return {"spec": "RFC-0012-A17", "hash_backend": "blake3-py 1.0.11 (official Rust backend)", "vectors": result}


def rejects(function, reason):
    try:
        function()
    except ValueError as error:
        assert str(error) == reason, (error, reason)
    else:
        raise AssertionError("accepted invalid input")


def checks():
    t = start(4)
    state = t.state
    for bits in (0, MAX_GRIND_BITS + 1):
        rejects(lambda: t.verify_grind(bits, 0), "InvalidGrindBits")
    nonce = start(4).grind(12)
    for bad in range(nonce):
        rejects(lambda: t.verify_grind(12, bad), "GrindMismatch")
    assert t.state == state
    t.verify_grind(12, nonce)
    assert t.state != state


if __name__ == "__main__":
    assert not sys.argv[1:], "unknown arguments"
    checks()
    fixture = pathlib.Path(__file__).resolve().parents[2] / "crates/stele-hash/tests/fixtures/grind.json"
    assert json.loads(fixture.read_text()) == vectors(), "grinding KAT fixture drift"
    print("A17 grinding vectors and rejections match the stele-hash KAT; no protocol coverage")
