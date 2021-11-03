import angr
import unittest

def test_registration():
    s = angr.SimState(arch='AMD64')

    a1 = s.solver.BVS('a', 64, key=(1,), eternal=True)
    a2 = s.solver.BVS('a', 64, key=(1,), eternal=True)
    unittest.TestCase().assertIs(a1, a2)

    b1 = s.solver.BVS('b', 64, key=(2,), eternal=False)
    s1 = s.copy()
    s2 = s.copy()

    b2 = s1.solver.BVS('b', 64, key=(2,), eternal=False)
    b3 = s2.solver.BVS('b', 64, key=(2,), eternal=False)
    unittest.TestCase().assertIs_not(b1, b2)
    unittest.TestCase().assertIs_not(b2, b3)
    unittest.TestCase().assertIs_not(b1, b3)

    a3 = s1.solver.BVS('a', 64, key=(1,), eternal=True)
    a4 = s2.solver.BVS('a', 64, key=(1,), eternal=True)
    unittest.TestCase().assertIs(a2, a3)
    unittest.TestCase().assertIs(a3, a4)

    unittest.TestCase().assertEqual(len(list(s.solver.get_variables(1))), 1)
    unittest.TestCase().assertEqual(len(list(s1.solver.get_variables(1))), 1)
    unittest.TestCase().assertEqual(len(list(s2.solver.get_variables(1))), 1)

    unittest.TestCase().assertEqual(len(list(s.solver.get_variables(2))), 1)
    unittest.TestCase().assertEqual(len(list(s1.solver.get_variables(2))), 2)
    unittest.TestCase().assertEqual(len(list(s2.solver.get_variables(2))), 2)

    unittest.TestCase().assertEqual(list(s.solver.describe_variables(a1)), [(1,)])
    unittest.TestCase().assertEqual(list(s.solver.describe_variables(b1)), [(2, 1)])
    unittest.TestCase().assertEqual(sorted(list(s.solver.describe_variables(a1 + b1))), [(1,), (2, 1)])
