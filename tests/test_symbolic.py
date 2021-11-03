import angr
import unittest

#def broken_symvalue():
#   # concrete symvalue
#   zero = SimValue(se.BVV(0, 64))
#   unittest.TestCase().assertFalse(zero.is_symbolic())
#   unittest.TestCase().assertEqual(zero.eval(), 0)
#   unittest.TestCase().assertRaises(ConcretizingException, zero.eval_exactly, 2)
#
#   # symbolic symvalue
#   x = se.BVS('x', 64)
#   sym = SimValue(x, constraints = [ x > 100, x < 200 ])
#   unittest.TestCase().assertTrue(sym.is_symbolic())
#   unittest.TestCase().assertEqual(sym.min_int(), 101)
#   unittest.TestCase().assertEqual(sym.max_int(), 199)
#   unittest.TestCase().assertCountEqual(sym.eval_upto(99), range(101, 200))
#   unittest.TestCase().assertRaises(ConcretizingException, zero.eval_exactly, 102)

def test_concretization_strategies():
    initial_memory = {0: b'A', 1: b'B', 2: b'C', 3: b'D'}

    s = angr.SimState(arch='AMD64', dict_memory_backer=initial_memory)

    # sanity check
    unittest.TestCase().assertEqual(s.solver.eval_upto(s.memory.load(3, size=1), 2, cast_to=bytes), [b'D'])

    x = s.solver.BVS('x', s.arch.bits)
    s.add_constraints(x >= 1)
    s.add_constraints(x <= 3)

    ss = s.copy()
    unittest.TestCase().assertEqual(tuple(sorted(ss.solver.eval_upto(ss.memory.load(x, 1), 10, cast_to=bytes))), (b'B', b'C', b'D'))

    ss = s.copy()
    x = s.solver.BVS('x', s.arch.bits)
    s.add_constraints(x >= 1)
    ss.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    ss.memory._create_default_read_strategies()
    unittest.TestCase().assertTrue('symbolic' in next(iter(ss.memory.load(x, 1).variables)))

#def test_concretization():
#   s = angr.SimState(arch="AMD64", mode="symbolic")
#   dst = s.solver.BVV(0x41424300, 32)
#   dst_addr = s.solver.BVV(0x1000, 64)
#   s.memory.store(dst_addr, dst, 4)
#
#   print "MEM KEYS", s.memory.mem.keys()
#   print "REG KEYS", s.registers.mem.keys()
#
#   print "TO NATIVE..."
#   s.set_native(True)
#   print "... done"
#
#   vv = s.native_env.vexecute(pyvex.IRExpr.Load("Iend_BE", "Ity_I32", pyvex.IRExpr.Const(pyvex.IRConst.U64(0x1000))))
#   unittest.TestCase().assertEqual(vv.str[:4], 'ABC\x00')
#   s.native_env.vexecute(pyvex.IRSB(bytes='\xb8\x41\x42\x43\x44'))
#
#   #import IPython; IPython.embed()
#   print "FROM NATIVE..."
#   s.set_native(False)
#   print "... done"
#
#   unittest.TestCase().assertEqual(s.reg_value(16).solver.eval(), 0x44434241)
#   print "YEAH"

#@nose.tools.timed(10)
def broken_symbolic_write():
    s = angr.SimState(arch='AMD64', mode='symbolic')

    addr = s.solver.BVS('addr', 64)
    s.add_constraints(s.solver.Or(addr == 10, addr == 20, addr == 30))
    unittest.TestCase().assertEqual(len(s.solver.eval_upto(addr, 10)), 3)

    s.memory.store(10, s.solver.BVV(1, 8))
    s.memory.store(20, s.solver.BVV(2, 8))
    s.memory.store(30, s.solver.BVV(3, 8))

    unittest.TestCase().assertTrue(s.solver.unique(s.memory.load(10, 1)))
    unittest.TestCase().assertTrue(s.solver.unique(s.memory.load(20, 1)))
    unittest.TestCase().assertTrue(s.solver.unique(s.memory.load(30, 1)))

    #print "CONSTRAINTS BEFORE:", s.constraints._solver.constraints
    #s.memory.store(addr, s.solver.BVV(255, 8), strategy=['symbolic','any'], limit=100)
    s.memory.store(addr, s.solver.BVV(255, 8))
    unittest.TestCase().assertTrue(s.satisfiable())

    unittest.TestCase().assertEqual(len(s.solver.eval_upto(addr, 10)), 3)
    unittest.TestCase().assertCountEqual(s.solver.eval_upto(s.memory.load(10, 1), 3), [ 1, 255 ])
    unittest.TestCase().assertCountEqual(s.solver.eval_upto(s.memory.load(20, 1), 3), [ 2, 255 ])
    unittest.TestCase().assertCountEqual(s.solver.eval_upto(s.memory.load(30, 1), 3), [ 3, 255 ])
    unittest.TestCase().assertEqual(len(s.solver.eval_upto(addr, 10)), 3)

    # see if it works when constraining the write address
    sa = s.copy()
    sa.add_constraints(addr == 20)
    unittest.TestCase().assertTrue(sa.satisfiable())
    unittest.TestCase().assertCountEqual(sa.solver.eval_upto(sa.memory.load(10, 1), 3), [ 1 ])
    unittest.TestCase().assertCountEqual(sa.solver.eval_upto(sa.memory.load(20, 1), 3), [ 255 ])
    unittest.TestCase().assertCountEqual(sa.solver.eval_upto(sa.memory.load(30, 1), 3), [ 3 ])
    unittest.TestCase().assertCountEqual(sa.solver.eval_upto(addr, 10), [ 20 ])

    # see if it works when constraining a value to the written one
    sv = s.copy()
    sv.add_constraints(sv.memory.load(30, 1) == 255)
    unittest.TestCase().assertTrue(sv.satisfiable())
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(sv.memory.load(10, 1), 3), [ 1 ])
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(sv.memory.load(20, 1), 3), [ 2 ])
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(sv.memory.load(30, 1), 3), [ 255 ])
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(addr, 10), [ 30 ])

    # see if it works when constraining a value to the unwritten one
    sv = s.copy()
    sv.add_constraints(sv.memory.load(30, 1) == 3)
    unittest.TestCase().assertTrue(sv.satisfiable())
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(sv.memory.load(10, 1), 3), [ 1, 255 ])
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(sv.memory.load(20, 1), 3), [ 2, 255 ])
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(sv.memory.load(30, 1), 3), [ 3 ])
    unittest.TestCase().assertCountEqual(sv.solver.eval_upto(addr, 10), [ 10, 20 ])

    s = angr.SimState(arch='AMD64', mode='symbolic')
    s.memory.store(0, s.solver.BVV(0x4141414141414141, 64))
    length = s.solver.BVS("length", 32)
    #s.memory.store(0, s.solver.BVV(0x4242424242424242, 64), symbolic_length=length)
    s.memory.store(0, s.solver.BVV(0x4242424242424242, 64))

    for i in range(8):
        ss = s.copy()
        ss.add_constraints(length == i)
        unittest.TestCase().assertEqual(ss.solver.eval(s.memory.load(0, 8), cast_to=bytes), b"B"*i + b"A"*(8-i))

def test_unsat_core():

    s = angr.SimState(arch='AMD64', mode='symbolic', add_options={ angr.options.CONSTRAINT_TRACKING_IN_SOLVER })
    x = s.solver.BVS('x', 32)
    s.add_constraints(s.solver.BVV(0, 32) == x)
    s.add_constraints(s.solver.BVV(1, 32) == x)

    unittest.TestCase().assertFalse(s.satisfiable())
    unsat_core = s.solver.unsat_core()
    unittest.TestCase().assertEqual(len(unsat_core), 2)


if __name__ == '__main__':
    test_unsat_core()
    test_concretization_strategies()
