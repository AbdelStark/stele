# Q23 finite expander bounds

[Haböck 2023/769](https://eprint.iacr.org/2023/769), §§3–5 and §6.2, supplies
the recursive construction, sampling analysis and M31 examples. The
[author-uploaded text](https://www.researchgate.net/publication/371339708_Brakedown%27s_expander_code)
was inspected; direct ePrint PDF access returned 403.

Our exact-integer study uses distinct uniform neighbors per row, independent
uniform F_p entries **including zero**, and no floating-point estimates. Run
`python3 research/code-provenance/check_expander.py`.

For input support k, degree d, neighbor threshold b and required image weight t:

```
graph failure <= C(n,k) C(m,b) [C(b,d)/C(m,d)]^k
entry failure <= C(n,k) (p-1)^k C(m,t-1) / p^(b-t+2)
```

Given expansion >b, image support below t leaves at least b-t+2 independently
uniform coordinates zero. Union over supports, nonzero input values and permitted
output supports gives the second bound. Exhaustive F3/F5 enumeration checks three cases.

The schedule N=2n, contraction 1/4, D=floor(N/50)+1 covers every power of
four from n=256 through 2^30. Below support 128 the checker uses exact
combinatorics; above it, the [rational interval derivation](../../formal/expander-sampling.md)
bounds the whole interval. It cross-checks those inequalities against exact
combinatorics at n=4096. All 200,431,782 events have bounds at most 2^-416;
their union is below 2^-388. These are sufficient sampling bounds, not fixed-setup certificates.

Production still needs authenticated setup/identity consumers, resource policy,
joint FS/H accounting and proximity parameters. E4-01 remains blocked; no registry,
encoder, profile admission, NC credit or benchmark result is delivered.

V2 strengthens the finite event budget to support the all-seed union in
[seeded-setup.md](../../formal/seeded-setup.md). For its exact 256-bit seed universe,
the ideal-oracle probability of any successfully regenerated bad supported map is
below 2^-132, irrespective of how a seed is selected. This is setup-only evidence;
concrete BLAKE3, proximity, actual source consumers and Q12 remain separate.
