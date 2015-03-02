'''
Created on Mar 2, 2015

@author: Stefan-Code
'''
import unittest
import os
from gglsbl3 import storage


class StorageTest(unittest.TestCase):

    def setUp(self):
        self.dbpath = "./testdb.sqlite"
        if os.path.exists(self.dbpath):
            os.remove(self.dbpath)
        self.storage = storage.SqliteStorage(self.dbpath)

    def tearDown(self):
        try:
            self.storage.total_cleanup()
        except Exception:
            raise

    def testName(self):
        pass


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
