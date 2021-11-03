import angr
import unittest

def test_file_unlink():
    # Initialize a blank state with an arbitrary errno location
    state = angr.SimState(arch="AMD64", mode="symbolic")
    state.libc.errno_location = 0xa0000000
    state.libc.errno = 0

    # Create a file 'test'
    fd = state.posix.open(b'test', 1)
    state.posix.close(fd)

    # Ensure 'test' was in fact created
    unittest.TestCase().assertIn(b'/test', state.fs._files)

    # Store the filename in memory
    path_addr = 0xb0000000
    state.memory.store(path_addr, b'test\x00')

    # Unlink 'test': should return 0 and leave ERRNO unchanged
    unlink = angr.SIM_PROCEDURES['posix']['unlink']()
    state.scratch.sim_procedure = unlink
    rval = unlink.execute(state, arguments=[path_addr]).ret_expr
    unittest.TestCase().assertEqual(rval, 0)
    unittest.TestCase().assertEqual(state.solver.eval(state.libc.errno), 0)

    # Check that 'test' was in fact deleted
    unittest.TestCase().assertEqual(state.fs._files, {})

    # Unlink again: should return -1 and set ERRNO to ENOENT
    unlink = angr.SIM_PROCEDURES['posix']['unlink']()
    state.scratch.sim_procedure = unlink
    rval = unlink.execute(state, arguments=[path_addr]).ret_expr
    unittest.TestCase().assertEqual(rval, -1)
    unittest.TestCase().assertEqual(state.solver.eval(state.libc.errno), state.posix.ENOENT)
