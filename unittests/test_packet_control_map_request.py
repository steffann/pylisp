#!/usr/bin/env python
from IPy import IP
from unittests.utils import PacketTest, PacketTestCreator

# Add the parent directory to the start of the path
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '.')
    sys.path.insert(0, '..')

from pylisp.packet.lisp.control import map_request
import doctest
import unittest


def load_tests(loader, tests, ignore):
    '''
    Add doctests to the test set
    '''
    tests.addTests(doctest.DocTestSuite(map_request))
    return tests


class MapRequestTestCase(unittest.TestCase):
    __metaclass__ = PacketTestCreator

    cases = [PacketTest(name='test_minimal_map_request',
                        desc='Generate a minimal map request',
                        cls=map_request.LISPMapRequestMessage,
                        params={'itr_rlocs': [IP('1.2.3.4')],
                                'eid_prefixes': [IP('192.0.2.0/24')]},
                        bytes_hex='1000000100000000000000000000'
                                  '00010102030400180001c0000200',
                        exception=(None, '')),
             ]


if __name__ == '__main__':
    unittest.main()
