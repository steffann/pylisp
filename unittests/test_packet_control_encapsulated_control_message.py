#!/usr/bin/env python

# Add the parent directory to the start of the path
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '..')

from IPy import IP
from bitstring import ConstBitStream
from pylisp.packet.control import encapsulated_control_message
import doctest
import unittest


def load_tests(loader, tests, ignore):
    '''
    Add doctests to the test set
    '''
    tests.addTests(doctest.DocTestSuite(encapsulated_control_message))
    return tests


if __name__ == '__main__':
    unittest.main()
