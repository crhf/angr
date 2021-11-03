import angr
from angr import SimState, SIM_PROCEDURES
from angr.engines import ProcedureEngine
import unittest
FAKE_ADDR = 0x100000

def test_procedure_actions():
    s = SimState(arch='AMD64')

    s.registers.store('rbx', 2)
    proc = SIM_PROCEDURES['testing']['retreg'](reg='rbx')
    succ = ProcedureEngine(None).process(s, procedure=proc)
    rbx = succ.artifacts['procedure'].ret_expr
    unittest.TestCase().assertIs(type(rbx), angr.state_plugins.SimActionObject)
    unittest.TestCase().assertEqual(s.solver.eval(rbx), 2)
    unittest.TestCase().assertEqual(rbx.reg_deps, { s.arch.registers['rbx'][0] })

if __name__ == '__main__':
    test_procedure_actions()
