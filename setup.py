#!/usr/bin/env python3

from setuptools import setup

import sys
import os

if not sys.version[0]  == "3":
    raise Exception("This Program is for Python **VERSION 3** only!")

__version__ = '0.1.4'
here = os.path.abspath(os.path.dirname(__file__))

# Get the long description from the relevant file
with open(os.path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(name='gglsbl3',
      version=__version__,
      description="Client library for Google Safe Browsing API",
      classifiers=[
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: Implementation :: CPython',
          'Intended Audience :: Developers',
          'Topic :: Internet',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],
      long_description=long_description,
      keywords='gglsbl3 gglsbl safebrowsing google-safe-browing googlesafebrowsing',
      author='Stefan Kuntz',
      author_email='Stefan.github@gmail.com',
      url='https://github.com/Stefan-Code/gglsbl3',
      license='Apache2',
      packages=['gglsbl3', 'gglsbl3.util'],
      install_requires=['argparse', 'python3-protobuf', ],
      scripts=['scripts/gglsbl_client.py'],
      )
