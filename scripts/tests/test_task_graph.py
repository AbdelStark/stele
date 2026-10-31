"""RFC-0020 §5: inference milestones must include their actual prerequisites."""
from pathlib import Path
import re
import unittest


GRAPH = Path(__file__).resolve().parents[2] / 'agents/tasks/graph.yaml'


def dependencies():
    # Read the task/dependency lists in this file's fixed, two-space layout.
    text = GRAPH.read_text()
    entries = re.findall(r'^- id: (\S+)\n(.*?)(?=^- id:|\Z)', text, re.M | re.S)
    result = {}
    for name, body in entries:
        if name in result:
            raise ValueError('duplicate task: ' + name)
        match = re.search(r'^  depends:(?: \[\])?\n((?:  - [^\n]+\n)*)', body, re.M)
        if match is None:
            raise ValueError('missing dependency list: ' + name)
        result[name] = tuple(line.removeprefix('  - ') for line in match[1].splitlines())
    if len(entries) != text.count('\n- id: '):
        raise ValueError('unparsed task')
    return result


class TaskGraphTests(unittest.TestCase):
    def test_accepts_known_acyclic_dependencies(self):
        graph = dependencies()
        visiting, complete = set(), set()

        def visit(task):
            self.assertIn(task, graph, 'unknown prerequisite')
            self.assertNotIn(task, visiting, 'dependency cycle')
            if task in complete:
                return
            visiting.add(task)
            self.assertEqual(len(graph[task]), len(set(graph[task])), 'duplicate prerequisite')
            for parent in graph[task]:
                visit(parent)
            visiting.remove(task)
            complete.add(task)

        for task in graph:
            visit(task)

    def test_requires_native_proving_and_verification_before_scale(self):
        graph = dependencies()

        def ancestors(task, seen=None):
            seen = set() if seen is None else seen
            for parent in graph[task]:
                if parent not in seen:
                    seen.add(parent)
                    ancestors(parent, seen)
            return seen

        required = {
            'E8-01': {'E6-03'} | {f'E7-{i:02}' for i in range(1, 11) if i != 7},
            'E8-06': {'E8-01', 'E8-02'},
            'E9-01': {'E8-01', 'E8-02', 'E8-05', 'E8-06'},
        }
        for milestone, prerequisites in required.items():
            with self.subTest(milestone=milestone):
                self.assertEqual(prerequisites - ancestors(milestone), set())


if __name__ == '__main__':
    unittest.main()
