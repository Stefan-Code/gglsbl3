'''
Created on Mar 2, 2015

@author: Stefan-Code
'''
import unittest
from gglsbl3 import client
import os
from nose.tools import *

class ClientTest(unittest.TestCase):

    def setUp(self):
        self.api_key = "abcdef"
        self.db_path = "./testdb.sqlite"
        self.client = client.SafeBrowsingList(self.api_key, self.db_path, discard_fair_use_policy=False)

    def tearDown(self):
        self.client._close_storage()
        os.remove(self.db_path)

    def testName(self):
        eq_(self.client.full_hash_protocol_client.config["url_args"]["key"], self.api_key)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
