#!/usr/bin/env python

# Add the parent directory to the start of the path
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '.')
    sys.path.insert(0, '..')

from copy import copy
from pylisp.packet.lisp.control import type_registry, ControlMessage
import doctest
import unittest


def load_tests(loader, tests, ignore):
    '''
    Add doctests to the test set
    '''
    tests.addTests(doctest.DocTestSuite(type_registry))
    return tests


class TypeRegistryTestCase(unittest.TestCase):
    def setUp(self):
        '''
        Store a backup of the type registry
        Because we're going to mess it up
        '''
        self.backup_type_registry = copy(type_registry._type_classes)
        type_registry._type_classes = {}

    def tearDown(self):
        '''
        Restore a clean copy of the type registry for further testing
        '''
        type_registry._type_classes = self.backup_type_registry

    def test_register_type_class(self):
        '''
        Normal registration of a type class
        '''
        class ValidType(ControlMessage):
            message_type = 1

        type_registry.register_type_class(ValidType)
        the_class = type_registry.get_type_class(1)
        self.assertEqual(the_class, ValidType)

    def test_wrong_class(self):
        '''
        Try to register a class of the wrong type
        '''
        class WrongType:
            pass

        with self.assertRaisesRegexp(ValueError, 'subclass'):
            type_registry.register_type_class(WrongType)

    def test_wrong_message_type(self):
        '''
        Try to register a class of the wrong type
        '''
        class WrongType(ControlMessage):
            message_type = 16

        with self.assertRaisesRegexp(ValueError, 'message.type'):
            type_registry.register_type_class(WrongType)

    def test_duplicate_registration_of_same_class(self):
        '''
        Try to register the same class twice
        '''
        class ValidType(ControlMessage):
            message_type = 1

        type_registry.register_type_class(ValidType)
        the_class = type_registry.get_type_class(1)
        self.assertEqual(the_class, ValidType)

        type_registry.register_type_class(ValidType)
        the_class = type_registry.get_type_class(1)
        self.assertEqual(the_class, ValidType)

    def test_bad_duplicate_registration(self):
        '''
        Try to register two classes for the same type
        '''
        class ValidType1(ControlMessage):
            message_type = 1

        class ValidType2(ControlMessage):
            message_type = 1

        type_registry.register_type_class(ValidType1)
        the_class = type_registry.get_type_class(1)
        self.assertEqual(the_class, ValidType1)

        with self.assertRaisesRegexp(ValueError, 'bound'):
            type_registry.register_type_class(ValidType2)

        the_class = type_registry.get_type_class(1)
        self.assertEqual(the_class, ValidType1)


if __name__ == '__main__':
    unittest.main()
