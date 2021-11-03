import unittest
import angr

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')
bina = os.path.join(test_location, "x86_64", "test_project_resolve_simproc")

"""
We voluntarily don't use SimProcedures for 'rand' and 'sleep' because we want
to step into their lib code.
"""

def test_bina():
    p = angr.Project(bina, exclude_sim_procedures_list=['rand', 'sleep'], load_options={"auto_load_libs":True})

    # Make sure external functions are not replaced with a SimProcedure
    sleep_jmpslot = p.loader.main_object.jmprel['sleep']
    rand_jmpslot = p.loader.main_object.jmprel['rand']
    read_jmpslot = p.loader.main_object.jmprel['read']

    sleep_addr = p.loader.memory.unpack_word(sleep_jmpslot.rebased_addr)
    rand_addr = p.loader.memory.unpack_word(rand_jmpslot.rebased_addr)
    read_addr = p.loader.memory.unpack_word(read_jmpslot.rebased_addr)

    libc_sleep_addr = p.loader.shared_objects['libc.so.6'].get_symbol('sleep').rebased_addr
    libc_rand_addr = p.loader.shared_objects['libc.so.6'].get_symbol('rand').rebased_addr

    unittest.TestCase().assertEqual(sleep_addr, libc_sleep_addr)
    unittest.TestCase().assertEqual(rand_addr, libc_rand_addr)
    unittest.TestCase().assertTrue(p.is_hooked(read_addr))
    unittest.TestCase().assertTrue("read" in
                           str(p._sim_procedures[read_addr]))

if __name__ == '__main__':
    test_bina()
