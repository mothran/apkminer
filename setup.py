#!/usr/bin/env python

from setuptools import setup

import pip
from pip.req import parse_requirements

install_reqs = parse_requirements("requirements.txt", session=pip.download.PipSession())
requirements = [str(ir.req) for ir in install_reqs]

setup(name              = 'apkminer',
      description       = 'Parallel APK vulnerability analyzer',
      author            = 'mothran',
      py_modules        = ['apkminer'],
      url               = 'http://github.com/mothran/apkminer',
      install_requires  = requirements,
      entry_points  = {
          'console_scripts': ['apkminer = apkminer:main']
          },
)
