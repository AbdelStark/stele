"""Q31 exact LogUp identities; no proof generator, verifier or NC credit."""
from collections import Counter
from itertools import product


def combine(left, right, p):
    a,b = left
    c,d = right
    return ((a*d+c*b) % p, b*d % p)


def tree(leaves, p, node=combine):
    leaves = list(leaves)
    while len(leaves) & (len(leaves)-1):
        leaves.append((0,1))
    while len(leaves) > 1:
        leaves = [node(leaves[i],leaves[i+1],p) for i in range(0,len(leaves),2)]
    return leaves[0]


def check_tree(node=combine):
    cases = 0
    for length in range(1,5):
        for values in product(range(3), repeat=length):
            for alpha in (3,4):
                leaves = [(1,(alpha-x) % 5) for x in values]
                numerator,denominator = tree(leaves,5,node)
                direct = sum(pow(alpha-x,-1,5) for x in values) % 5
                assert denominator != 0
                assert numerator*pow(denominator,-1,5) % 5 == direct
                cases += 1
    assert cases == 240
    return cases


def multiply(a,b,p):
    out = [0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b):
            out[i+j] = (out[i+j]+x*y) % p
    return out


def numerator(residues,p):
    """Clear distinct poles; do not confuse zero residues with absent factors."""
    out = [0]*len(residues)
    for pole,residue in residues.items():
        term = [residue % p]
        for other in residues:
            if other != pole:
                term = multiply(term,[-other % p,1],p)
        for i,x in enumerate(term):
            out[i] = (out[i]+x) % p
    return out


def check_bounded_counts():
    cases = bad = 0
    for length in range(1,5):
        for values in product(range(3), repeat=length):
            for m0,m1 in product(range(5), repeat=2):
                residues = dict(Counter(values))
                residues[0] = residues.get(0,0)-m0
                residues[1] = residues.get(1,0)-m1
                coefficients = numerator(residues,5)
                for alpha in range(5):
                    evaluated = sum(c*pow(alpha,i,5) for i,c in enumerate(coefficients)) % 5
                    if alpha not in residues:
                        fractional = sum(r*pow(alpha-x,-1,5) for x,r in residues.items()) % 5
                        denominator = 1
                        for x in residues:
                            denominator = denominator*(alpha-x) % 5
                        assert evaluated == fractional*denominator % 5
                if 2 in values:
                    assert any(coefficients)  # no table multiplicities erase this pole
                    bad += 1
                cases += 1
    assert (cases,bad) == (3000,2250)
    return cases,bad


def f9_add(a,b):
    return tuple((x+y) % 3 for x,y in zip(a,b))


def f9_mul(a,b):
    # F_3[u]/(u^2+1); -1 is not a square in F_3.
    return ((a[0]*b[0]-a[1]*b[1]) % 3, (a[0]*b[1]+a[1]*b[0]) % 3)


def check():
    cases = check_tree()
    try:
        check_tree(lambda left,right,p:
                   ((left[0]*right[1]-right[0]*left[1]) % p,left[1]*right[1] % p))
    except AssertionError:
        pass
    else:
        raise AssertionError('fraction-tree sign mutant survived')
    bounded,bad = check_bounded_counts()
    collapse = 0
    for p in (3,5,7,11,17):
        for alpha in range(p):
            if alpha in (0,2):
                continue
            a,b = tree([(1,(alpha-2) % p)]*p,p)
            assert a == 0 and b != 0  # p invalid copies versus table {0}, m=0
            chunks = [p-1,1]
            parts = [n*pow(alpha-2,-1,p) % p for n in chunks]
            assert all(parts) and sum(parts) % p == 0
            collapse += 1
    assert collapse == 33
    domain = list(product(range(3),repeat=2))
    extension = []
    for alpha in domain:
        if alpha in ((0,0),(2,0)):
            continue
        difference = f9_add(alpha,(1,0))
        inverse, = [x for x in domain if f9_mul(x,difference) == (1,0)]
        total = (0,0)
        for _ in range(3):
            total = f9_add(total,inverse)
        assert total == (0,0)
        extension.append(alpha)
    assert len(list(product(extension,repeat=2))) == 49
    # Cross multiplication alone is vacuous at two zero-denominator leaves.
    assert tree([(1,0),(1,0)],5) == (0,0)
    assert tree([(0,0),(1,3)],5) == (0,0)
    assert tree([(0,1),(1,3)],5) == (1,3)
    compression = 0
    for width in (2,3):
        table = [(0,)*width,(1,)*width]
        for value in product(range(5),repeat=width):
            if value in table:
                continue
            collisions = 0
            for beta in range(5):
                pack = lambda row: sum(x*pow(beta,i,5) for i,x in enumerate(row)) % 5
                collisions += pack(value) in [pack(row) for row in table]
            assert collisions <= (width-1)*len(table)
            compression += 1
    assert compression == 146
    p = (1 << 31)-1
    n = 1 << 37
    assert p % p == 0 and n > p
    assert (n+(p-2))//(p-1) == 65
    assert n//(1 << 30) == 128
    assert 128*(1 << 16) == 8388608
    print(f'{cases} fraction trees; sign mutant rejected; {bounded} residue identities ({bad} invalid bounded cases nonzero)')
    print(f'{collapse} characteristic collapses; 7 F_9 challenges / 49 pairs also collapse; pole/padding diagnostics pass')
    print(f'{compression} tuple compression cases; partition residuals nonzero individually but cancel when merged')
    print('Q31 research only: no native LogUp, profile, NC or measured cost result')


if __name__ == '__main__':
    check()
