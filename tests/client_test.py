'''
Testing of the gglsbl3 client module (high level api)
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
        try:
            os.remove(self.db_path)
        except:
            print("error cleaning up database file, still in use??")

    def test_api_key(self):
        eq_(self.client.full_hash_protocol_client.config["url_args"]["key"], self.api_key)

    def test_update_hash_prefix_cache(self):
        mock_url = 'https://safebrowsing.google.com/safebrowsing/downloads?key={api_key}&pver=3.0&appver=0.1&client=api'

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
