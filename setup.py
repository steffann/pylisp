#!/usr/bin/env python
'''
Created on 12 jan. 2013

@author: sander
'''

from setuptools import setup, find_packages
from version import get_git_version
import glob


setup(name='pylisp',
      version=get_git_version(),
      author='S.J.M. Steffann',
      author_email='sander@steffann.nl',
      license='BSD License',
      url='https://github.com/steffann/pylisp',
      keywords='lisp ddt',
      description='Locator/ID Separation Protocol (LISP) library',
      long_description=open('README.md').read().strip(),
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

      test_suite='test',
      packages=find_packages(exclude=['unittests']),
      scripts=glob.glob('scripts/*'),

      setup_requires=["setuptools_git >= 0.3"],
      install_requires=['IPy',
                        'bitstring'])
