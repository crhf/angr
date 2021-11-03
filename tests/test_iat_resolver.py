import unittest
import os

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_iat():
    p = angr.Project(os.path.join(test_location, 'i386', 'simple_windows.exe'), auto_load_libs=False)
    cfg = p.analyses.CFGFast()

    strcmp_caller_bb = cfg.get_any_node(0x401010)
    unittest.TestCase().assertEqual(len(strcmp_caller_bb.successors), 1)

    strcmp = strcmp_caller_bb.successors[0]
    unittest.TestCase().assertTrue(strcmp.is_simprocedure)
    unittest.TestCase().assertEqual(strcmp.simprocedure_name, 'strcmp')

    strcmp_successors = strcmp.successors
    unittest.TestCase().assertEqual(len(strcmp_successors), 1)

    strcmp_ret_to = strcmp_successors[0]
    unittest.TestCase().assertEqual(strcmp_ret_to.addr, 0x40102a)

if __name__ == '__main__':
    test_iat()
