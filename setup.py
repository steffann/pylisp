#!/usr/bin/env python
'''
Created on 12 jan. 2013

@author: sander
'''

from setuptools import setup, find_packages
from version import get_git_version
import glob

desc = '''This package provides an implementation of LISP, the Locator/ID
Separation Protocol in Python. This is an experimental protocol
where the IP addresses on the network define the identity of
the systems and a separate mapping system determines how the
data is routed to that network.

This library provides the means to parse and create LISP data
and control messages, as well as command line tools to perform
actions like asking a map resolver for a mapping and directly
querying a DDT node.

The intention is that in a later stage implementations for a
map server, map resolver and DDT node will also be provided.'''

setup(name='pylisp',
      version=get_git_version(),
      author='S.J.M. Steffann',
      author_email='sander@steffann.nl',
      license='BSD',
      url='https://github.com/steffann/pylisp',
      description='Locator/ID Separation Protocol (LISP) library',
      long_description=desc,
      classifiers=['Development Status :: 2 - Pre-Alpha',
                   'Environment :: Console',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'License :: OSI Approved :: BSD License',
                   'Natural Language :: English',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Topic :: Communications',
                   'Topic :: Internet',
                   'Topic :: Software Development :: Libraries',
                   'Topic :: System :: Networking',
                   'Topic :: Utilities'],
      platforms=[],
      test_suite='test',
      packages=find_packages(exclude=['unittests']),
      scripts=glob.glob('scripts/*'))
