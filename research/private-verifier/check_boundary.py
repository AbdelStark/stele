"""Q30 finite knowledge/language boundary; not a wrapper or cryptographic theorem."""
from fractions import Fraction


def solver(oracle, size, budget, start, step):
    """A query-bounded search; only oracle answers reveal a candidate witness."""
    for i in range(budget):
        candidate = (start+step*i) % size
        if oracle(candidate):
            return candidate
    return None


def check_search(search):
    cases = 0
    for bits in range(1,9):
        size = 1 << bits
        for budget in sorted({0,1,size//2,size-1,size}):
            for start,step in ((0,1),(size-1,3),(size//2,5)):
                successes = 0
                for secret in range(size):
                    reads = []
                    def oracle(candidate):
                        assert 0 <= candidate < size
                        reads.append(candidate)
                        return candidate == secret
                    witness = search(oracle,size,budget,start,step)
                    assert len(reads) <= budget and len(set(reads)) == len(reads)
                    if witness is not None:
                        assert witness == secret and witness in reads
                        successes += 1
                    # The existential statement is true for every secret oracle,
                    # even when this bounded solver cannot produce its witness.
                    assert sum(candidate == secret for candidate in range(size)) == 1
                assert Fraction(successes,size) == Fraction(budget,size)
                cases += 1
    assert cases == 114
    return cases


def check():
    cases = check_search(solver)
    # Isolated search mutants: an unqueried guess and a repeated candidate.
    # These are diagnostics of this finite experiment, not wrapper controls.
    for mutant in (lambda *args: 0,
                   lambda oracle,size,budget,start,step:
                       solver(oracle,size,budget,start,0)):
        try:
            check_search(mutant)
        except AssertionError:
            pass
        else:
            raise AssertionError('search mutant survived')
    # Arithmetic checks on the inspected upstream target, not a full FRI bound.
    assert [pow_bits+queries*blowup for pow_bits,queries,blowup in ((26,70,1),(26,35,2),(27,23,3))] == [96]*3
    assert 96 < 100 < 128
    print(f'{cases} finite oracle/search cases: existential language membership is always true; bounded witness search remains q/N')
    print('two isolated search mutants rejected')
    print('upstream configured target arithmetic: 96 bits; no Stele profile or extraction/security theorem inferred')
    print('Q30 research only: no proof generator/verifier, simulator, NC credit or native performance claim')


if __name__ == '__main__':
    check()
