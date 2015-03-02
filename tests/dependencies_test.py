'''
Created on Mar 2, 2015

@author: Stefan-Code
'''
import unittest

class DependenciesTest(unittest.TestCase):

    def testProtobuf(self):
        from google.protobuf import descriptor as _descriptor
        from google.protobuf import message as _message
        from google.protobuf import reflection as _reflection
        from google.protobuf import descriptor_pb2

    def testUrllib(self):
        from urllib import request

    def testOther(self):
        import struct
        import time
        from io import BytesIO
        import random
        import posixpath
        import re
        import hashlib
        import socket

    def testDevDependencies(self):
        import unittest
        import httpretty
        import nose.tools

    def testSqlite3(self):
        import sqlite3


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
