"""RFC-0010 A3 v2 expander query policy and Fiat-Shamir round findings.

Exact integer checks only. Supplies no native parity, NC credit or profile.
"""
P = (1 << 31)-1
# Policy 1 for field-source version 2, indexed by J=3..14 (k=4^J, N=2k).
CERT = (478, 11489, 13137, 13377, 13438, 13469, 13469, 13471, 13472, 13472, 13472, 13472)
OPEN = (221, 5722, 6546, 6666, 6697, 6708, 6713, 6713, 6713, 6714, 6714, 6714)


def geometry(j):
    # code-identity.md §2; recomputed here, not imported from the catalog.
    k = 4**j
    n = 2*k
    distance = 64 if j == 3 else k//25+1
    return n, distance, (distance-1)//3


def passes(n, hit, q, bits):
    return ((n-hit)**q << bits) <= n**q


def check_policy():
    for j, cert, opening in zip(range(3, 15), CERT, OPEN, strict=True):
        n, distance, radius = geometry(j)
        assert n <= 1 << 30, 'A10 sampler supports N<=2^30 only'
        for q, hit in ((cert, radius+1), (opening, distance-radius)):
            assert 1 <= q < 1 << 16
            assert passes(n, hit, q, 130) and not passes(n, hit, q-1, 130)
    # J=3 is the base-only map: same counts as Circle(6,1) in Policy 1.
    assert (CERT[0], OPEN[0]) == (478, 221)
    # J=15 has N=2^31, outside the A10 sampler: unsupported, never truncated.
    assert geometry(15)[0] == 1 << 31


def fs_round_exceeds(q_hash, target_bits, numerator, denominator):
    """True when q_hash * numerator/denominator > 2^-target_bits."""
    return q_hash*numerator << target_bits > denominator


def check_fs_findings():
    q_treaty, q_standard = 1 << 100, 1 << 80
    # Query rounds at the 2^-130 interactive policy fail both profiles under
    # RFC-0012 §4's Q*max-round charge (2^-30 treaty, 2^-50 standard).
    j = 14
    n, distance, radius = geometry(j)
    q = CERT[-1]
    assert fs_round_exceeds(q_treaty, 128, (n-radius-1)**q, n**q)
    assert fs_round_exceeds(q_standard, 100, (n-radius-1)**q, n**q)
    # Certificate tensor round 2*ell*h/|K|, ell=20, largest v2 and Circle sizes.
    ell = 20
    for h in (radius+1, ((1 << 30)-(1 << 28)-1)//3+1):
        for degree, q_hash, bits in ((8, q_treaty, 128), (4, q_treaty, 128), (4, q_standard, 100)):
            assert fs_round_exceeds(q_hash, bits, 2*ell*h, P**degree)
        # Standard OM31 passes this one round; it is not a complete profile bound.
        assert not fs_round_exceeds(q_standard, 100, 2*ell*h, P**8)
    # Least counts at treaty's 2^-228 per query round (A3 item 7), largest sizes.
    for n, distance, cert, opening in (
            (1 << 21, (1 << 21)-(1 << 20), 867, 390), (1 << 30, (1 << 30)-(1 << 29), 867, 390),
            (1 << 22, (1 << 22)-(1 << 20), 550, 228), (1 << 30, (1 << 30)-(1 << 28), 550, 228),
            (*geometry(14)[:2], 23627, 11774)):
        radius = (distance-1)//3
        for q, hit in ((cert, radius+1), (opening, distance-radius)):
            assert passes(n, hit, q, 228) and not passes(n, hit, q-1, 228)
    # Treaty OM31 tensor round needs 2^229*ell*h <= p^8: 2^18 passes, 2^19 fails.
    assert not fs_round_exceeds(q_treaty, 128, 2*(1 << 18), P**8)
    assert fs_round_exceeds(q_treaty, 128, 2*(1 << 19), P**8)


def check_native():
    """Compare the native verifier-derived values with the exact rows checked above."""
    from pathlib import Path
    import subprocess
    result = subprocess.run(['cargo', 'run', '-q', '-p', 'stele-pcs', '--example',
                             'expander_policy', '--locked', '--offline'],
                            cwd=Path(__file__).resolve().parents[2], check=True,
                            capture_output=True, text=True)
    native = [[int(value) for value in line.split()] for line in result.stdout.splitlines()]
    # A3 item 3 / RFC-0012 A15: the setup term applies exactly at J>=4.
    expected = [[j, *geometry(j), cert, opening, int(j >= 4)]
                for j, cert, opening in zip(range(3, 15), CERT, OPEN, strict=True)]
    assert native == expected, 'native v2 geometry/query policy differs from checked values'


if __name__ == '__main__':
    import sys
    check_policy()
    check_fs_findings()
    if sys.argv[1:] == ['--native']:
        check_native()
        print('12 native v2 query pairs match exact independently checked minima')
    else:
        assert not sys.argv[1:], 'unknown arguments'
    print('12 minimal v2 query pairs; J=15 unsupported; FS round findings hold')
