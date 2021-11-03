import os
import angr
import claripy
import unittest
from angr.codenode import BlockNode, HookNode, SyscallNode

BIN_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')

def test_ret_float():
    p = angr.load_shellcode(b'X', arch='i386')

    class F1(angr.SimProcedure):
        def run(self):
            return 12.5

    p.hook(0x1000, F1(cc=p.factory.cc(func_ty=angr.sim_type.parse_file('float (x)();')[0]['x'])))
    p.hook(0x2000, F1(cc=p.factory.cc(func_ty=angr.sim_type.parse_file('double (x)();')[0]['x'])))

    s = p.factory.call_state(addr=0x1000, ret_addr=0)
    succ = s.step()
    unittest.TestCase().assertEqual(len(succ.successors), 1)
    s2 = succ.flat_successors[0]
    unittest.TestCase().assertFalse(s2.regs.st0.symbolic)
    unittest.TestCase().assertEqual(s2.solver.eval(s2.regs.st0.get_bytes(4, 4).raw_to_fp()), 12.5)

    s = p.factory.call_state(addr=0x2000, ret_addr=0)
    succ = s.step()
    unittest.TestCase().assertEqual(len(succ.successors), 1)
    s2 = succ.flat_successors[0]
    unittest.TestCase().assertFalse(s2.regs.st0.symbolic)
    unittest.TestCase().assertEqual(s2.solver.eval(s2.regs.st0.raw_to_fp()), 12.5)

def test_syscall_and_simprocedure():
    bin_path = os.path.join(BIN_PATH, 'tests', 'cgc', 'CADET_00002')
    proj = angr.Project(bin_path)
    cfg = proj.analyses.CFGFast(normalize=True)

    # check syscall
    node = cfg.get_any_node(proj.loader.kernel_object.mapped_base + 1)
    func = proj.kb.functions[node.addr]

    unittest.TestCase().assertTrue(node.is_simprocedure)
    unittest.TestCase().assertTrue(node.is_syscall)
    unittest.TestCase().assertFalse(node.to_codenode().is_hook)
    unittest.TestCase().assertFalse(proj.is_hooked(node.addr))
    unittest.TestCase().assertTrue(func.is_syscall)
    unittest.TestCase().assertTrue(func.is_simprocedure)
    unittest.TestCase().assertEqual(type(proj.factory.snippet(node.addr)), SyscallNode)

    # check normal functions
    node = cfg.get_any_node(0x80480a0)
    func = proj.kb.functions[node.addr]

    unittest.TestCase().assertFalse(node.is_simprocedure)
    unittest.TestCase().assertFalse(node.is_syscall)
    unittest.TestCase().assertFalse(proj.is_hooked(node.addr))
    unittest.TestCase().assertFalse(func.is_syscall)
    unittest.TestCase().assertFalse(func.is_simprocedure)
    unittest.TestCase().assertEqual(type(proj.factory.snippet(node.addr)), BlockNode)

    # check hooked functions
    proj.hook(0x80480a0, angr.SIM_PROCEDURES['libc']['puts']())
    cfg = proj.analyses.CFGFast(normalize=True)# rebuild cfg to updated nodes
    node = cfg.get_any_node(0x80480a0)
    func = proj.kb.functions[node.addr]

    unittest.TestCase().assertTrue(node.is_simprocedure)
    unittest.TestCase().assertFalse(node.is_syscall)
    unittest.TestCase().assertTrue(proj.is_hooked(node.addr))
    unittest.TestCase().assertFalse(func.is_syscall)
    unittest.TestCase().assertTrue(func.is_simprocedure)
    unittest.TestCase().assertEqual(type(proj.factory.snippet(node.addr)), HookNode)


if __name__ == '__main__':
    test_ret_float()
    test_syscall_and_simprocedure()
