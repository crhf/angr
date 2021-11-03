import unittest
import angr
import networkx

import os
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_kb_plugins():
    p = angr.Project(os.path.join(location, 'x86_64', 'fauxware'))

    unittest.TestCase().assertIsInstance(p.kb.data, angr.knowledge_plugins.Data)
    unittest.TestCase().assertIsInstance(p.kb.functions, angr.knowledge_plugins.FunctionManager)
    unittest.TestCase().assertIsInstance(p.kb.variables, angr.knowledge_plugins.VariableManager)
    unittest.TestCase().assertIsInstance(p.kb.labels, angr.knowledge_plugins.Labels)
    unittest.TestCase().assertIsInstance(p.kb.comments, angr.knowledge_plugins.Comments)

    unittest.TestCase().assertIsInstance(p.kb.callgraph, networkx.Graph)
    unittest.TestCase().assertIsInstance(p.kb.resolved_indirect_jumps, dict)
    unittest.TestCase().assertIsInstance(p.kb.unresolved_indirect_jumps, set)

    unittest.TestCase().assertIsNotNone(dir(p.kb))
    for plugin in ['data', 'functions', 'variables', 'labels', 'comments', 'callgraph', 'resolved_indirect_jumps', 'unresolved_indirect_jumps']:
        unittest.TestCase().assertIn(plugin, dir(p.kb))


if __name__ == '__main__':
    test_kb_plugins()
