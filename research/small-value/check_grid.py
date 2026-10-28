"""Research-only MSB grid expansion check; no timing/production-control credit."""
import itertools
import random
P=2**31-1


def extend_axis_by_axis(boolean, k, width):
    grid=[v%P for v in boolean]
    assert len(grid)==2**k
    for h in range(k):
        suffix=2**(k-h-1)
        out=[]
        for prefix in range(width**h):
            offset=prefix*2*suffix
            for node in range(width):
                out.extend((grid[offset+z]+node*(grid[offset+suffix+z]-grid[offset+z]))%P for z in range(suffix))
        grid=out
    return grid


def direct(boolean,k,width):
    grid=[]
    for nodes in itertools.product(range(width),repeat=k):
        total=0
        for b,value in enumerate(boolean):
            weight=1
            for h,x in enumerate(nodes):weight*=x if b>>(k-h-1)&1 else 1-x
            total+=value*weight
        grid.append(total%P)
    return grid


def checks():
    rng=random.Random(200400)
    count=0
    for degree in range(5):
        width=max(2,degree+1)
        for k in range(5):
            for _ in range(20):
                values=[rng.choice([-32768,65535,0,1,rng.randrange(-32768,65536)]) for _ in range(2**k)]
                assert extend_axis_by_axis(values,k,width)==direct(values,k,width),(degree,k)
                count+=1
    print(f'{count} axis-expanded grids match direct integer MLE evaluation modulo M31; MSB order and all k<=4/degree<=4.',flush=True)
    # An axis-order permutation must be observable on a non-symmetric table.
    a=extend_axis_by_axis([1,3,7,11],2,5)
    b=extend_axis_by_axis([1,7,3,11],2,5)
    assert a!=b and a[1]!=b[1]
    print('Swapped-axis mutation changes the checked grid.',flush=True)

if __name__=='__main__':checks()
