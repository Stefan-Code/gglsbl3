#!/usr/bin/env python2.7

from setuptools import setup

import sys, os

__version__ = '0.3'

setup(name='gglsbl3',
    version=__version__,
    description="Client library for Google Safe Browsing API",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='safe browsing api client',
    author='Stefan-Code',
    author_email='Stefan-Code@users.noreply.github.com',
    url='https://github.com/Stefan-Code/gglsbl3',
    license='Apache2',
    packages=['gglsbl'],
    install_requires=['argparse', 'pysqlite', 'protobuf'],
    #  scripts=['bin/gglsbl_client.py'],
)
