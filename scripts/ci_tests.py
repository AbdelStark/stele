#!/usr/bin/env python3
"""RFC-0020 §5: quick tooling checks; copied-source mutations run separately."""
import argparse
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def cases(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from cases(test)
        else:
            yield test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutant-matrix', action='store_true')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'scripts/tests'))
    tests = list(cases(suite))
    mutants = [test for test in tests if test.id().startswith('test_gates.')]
    quick = [test for test in tests if not test.id().startswith('test_gates.')]
    assert mutants and quick and len(mutants) + len(quick) == len(tests)
    if args.mutant_matrix:
        print('matrix=' + json.dumps({'test': [test.id() for test in mutants]}))
        return 0
    return not unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(quick)).wasSuccessful()


if __name__ == '__main__':
    sys.exit(main())
