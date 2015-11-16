'''
Tests for the gglsbl3.util package
'''
import unittest
from gglsbl3 import util
from nose.tools import *

class FormatUtilTest(unittest.TestCase):
    '''
    Test the formatting utils
    '''
    def test_prettify_seconds(self):
        eq_(util.prettify_seconds(1), '1 second')
        eq_(util.prettify_seconds(2), '2 seconds')
        eq_(util.prettify_seconds(60), '1 minute')
        eq_(util.prettify_seconds(62), '1 minute and 2 seconds')
        eq_(util.prettify_seconds(60*60), '1 hour')
        eq_(util.prettify_seconds(3600 + 2), '1 hour and 2 seconds')
        eq_(util.prettify_seconds(60*60+62), '1 hour, 1 minute and 2 seconds')
        eq_(util.prettify_seconds(86400), '1 day')

    @raises(ValueError)
    def test_prettify_seconds_error(self):
        util.prettify_seconds(-5)

    def test_format_max_len(self):
        eq_(util.format_max_len('abcdefghijklmnopqrstuvwxyz'), 'abcde[...]vwxyz')
        eq_(util.format_max_len('abcdefghijklmnop'), 'abcde[...]lmnop')
        eq_(util.format_max_len('abcdefghijklmno'), 'abcdefghijklmno')
        eq_(util.format_max_len('a'), 'a')

class NetworkUtilTest(unittest.TestCase):
    '''
    Test the network utils
    '''
    def setUp(self):
        self.ip_pairs = [('127.0.0.1', 2130706433), ('188.198.144.123', 3167129723), ('8.8.8.8', 134744072)]

    def test_ip_to_int(self):
        for ip, ip_int in self.ip_pairs:
            eq_(util.ip_to_int(ip), ip_int)

    def test_int_to_ip(self):
        for ip, ip_int in self.ip_pairs:
            eq_(util.int_to_ip(ip_int), ip)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
