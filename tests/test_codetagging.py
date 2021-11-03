
import os

import unittest

import angr
from angr.analyses.code_tagging import CodeTags

tests_base = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '..', '..', 'binaries', 'tests')


def test_hasxor():
    p = angr.Project(os.path.join(tests_base, 'x86_64', 'HashTest'), auto_load_libs=False)
    cfg = p.analyses.CFG()

    ct_rshash = p.analyses.CodeTagging(cfg.kb.functions['RSHash'])
    unittest.TestCase().assertNotIn(CodeTags.HAS_XOR, ct_rshash.tags)
    ct_jshash = p.analyses.CodeTagging(cfg.kb.functions['JSHash'])
    unittest.TestCase().assertIn(CodeTags.HAS_XOR, ct_jshash.tags)
    unittest.TestCase().assertIn(CodeTags.HAS_BITSHIFTS, ct_jshash.tags)
    ct_elfhash = p.analyses.CodeTagging(cfg.kb.functions['ELFHash'])
    unittest.TestCase().assertIn(CodeTags.HAS_BITSHIFTS, ct_elfhash.tags)


if __name__ == "__main__":
    test_hasxor()
