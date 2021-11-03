import tempfile
import os
import logging

import unittest

import angr


l = logging.getLogger("angr_tests.managers")

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def broken_cacher():
    p = angr.Project(os.path.join(location, 'x86_64', 'fauxware'), load_options={'auto_load_libs': False})

    tmp_dir = tempfile.mkdtemp(prefix='test_cacher_container')
    container = os.path.join(tmp_dir, '%s.cache' % os.path.basename(p.filename))

    pg = p.factory.simulation_manager()
    pg.use_technique(angr.exploration_techniques.Cacher(when=0x4006ee, container=container))
    pg.run()

    pg2 = p.factory.simulation_manager()
    pg2.use_technique(angr.exploration_techniques.Cacher(container=container))
    unittest.TestCase().assertEqual(pg2.active[0].addr, 0x4006ed)

    pg2.run()

    unittest.TestCase().assertEqual(len(pg2.deadended), len(pg.deadended))
    unittest.TestCase().assertTrue(pg2.deadended[0].addr in [s.addr for s in pg.deadended])
    unittest.TestCase().assertTrue(pg2.deadended[1].addr in [s.addr for s in pg.deadended])
    unittest.TestCase().assertTrue(pg2.deadended[2].addr in [s.addr for s in pg.deadended])

if __name__ == "__main__":
    broken_cacher()
