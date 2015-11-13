'''
Created on Mar 2, 2015

@author: Stefan-Code
'''
import unittest
import os
import pickle
import copy

from gglsbl3 import storage
from nose.tools import *


class StorageTest(unittest.TestCase):

    def setUp(self):
        self.dbpath = "./testdb.sqlite"
        if os.path.exists(self.dbpath):
            os.remove(self.dbpath)
        self.storage = storage.SqliteStorage(self.dbpath)
        with open('tests/fake_chunk.pickle', 'rb') as fake_chunk_file:
            self.fake_chunk = pickle.load(fake_chunk_file)
        self.fake_chunk_other = copy.copy(self.fake_chunk)
        self.fake_chunk_other.chunk_number += 1
    def tearDown(self):
        try:
            self.storage.total_cleanup()
            self.storage.close()
            os.remove(self.dbpath)
        except Exception:
            raise

    def test_expand_ranges(self):
        compressed_ranges_list = ['1-4,7', '9-11', '50']
        expanded_ranges = [1,2,3,4,7,9,10,11,50]
        eq_(storage.StorageBase.expand_ranges(compressed_ranges_list), expanded_ranges)

    def test_compress_ranges(self):
        compressed_ranges = '1-4,7'
        expanded_ranges = [1,2,3,4,7]
        eq_(storage.StorageBase.compress_ranges(expanded_ranges), compressed_ranges)

    @raises(ValueError)
    def test_expand_ranges_fail(self):
        _result = storage.StorageBase.expand_ranges(['1--7,-'])

    def test_store_chunk(self):
        self.storage.store_chunk(self.fake_chunk)

    def test_chunk_exists(self):
        self.test_store_chunk()
        ok_(self.storage.chunk_exists(self.fake_chunk))

    def test_chunk_not_exists(self):
        ok_(not self.storage.chunk_exists(self.fake_chunk_other))

        

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
