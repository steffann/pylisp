#!/usr/bin/env python
import unittest


def load_tests(loader, tests, pattern):
    new_tests = unittest.defaultTestLoader.discover('unittests')
    tests.addTests(new_tests)
    return tests


if __name__ == '__main__':
    unittest.main()
