import angr
import os
import unittest

test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '..', '..', 'binaries', 'tests', '')

def test_static_hooker():
    test_file = os.path.join(test_location, 'x86_64', 'static')
    p = angr.Project(test_file)
    sh = p.analyses.StaticHooker('libc.so.6')

    unittest.TestCase().assertIn(4197616, sh.results)
    unittest.TestCase().assertIs(type(sh.results[4197616]), angr.SIM_PROCEDURES['glibc']['__libc_start_main'])
    unittest.TestCase().assertIs(type(p.hooked_by(4197616)), angr.SIM_PROCEDURES['glibc']['__libc_start_main'])

if __name__ == '__main__':
    test_static_hooker()
