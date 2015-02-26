'''
Created on Feb 18, 2015

@author: SK
'''
import unittest
import urllib
from gglsbl3 import protocol
import time
import sys
import logging
import httpretty
from nose.tools import *
log = logging.getLogger()
log.setLevel(logging.DEBUG)
if not log.handlers:
    log.addHandler(logging.StreamHandler(sys.stdout))


class BaseProtocolTest(unittest.TestCase):

    def setUp(self):
        self.api_key = "abcdefg"
        self.client = protocol.BaseProtocolClient(api_key=self.api_key, discard_fair_use_policy=False)

    def tearDown(self):
        pass

    def testBaseProtocolClientInit(self):
        assert_equal(self.client.config["url_args"]["key"], "abcdefg")
        assert_false(self.client.discard_fair_use_policy)

    def testSetNextCallTimeOut(self, delay=30):
        self.client.set_next_call_timeout(delay)
        # log.debug("next call timestamp is: "+ str(self.client._next_call_timestamp))
        assert_equal(self.client._next_call_timestamp, int(time.time()) + delay)

    def testGetFairUseDelay(self):
        self.testSetNextCallTimeOut(10)
        delay = self.client.get_fair_use_delay()
        assert_in(delay, [9, 10])
        self.client._error_count = 1
        assert_equal(self.client.get_fair_use_delay(), 60)
        self.client._error_count = 2
        log.debug("delay is: " + str(self.client.get_fair_use_delay()))
        assert_less_equal(self.client.get_fair_use_delay(), 28800)
        self.client._error_count = 20
        assert_less_equal(self.client.get_fair_use_delay(), 28800)

    def testFairUseDelay(self):
        self.client.set_next_call_timeout(2)
        time1 = time.time()
        self.client.fair_use_delay()
        time2 = time.time()
        delta = time2 - time1
        assert_equal(int(round(delta)), 2)

    def testMkUrl(self):
        url = self.client.mkUrl("downloads")
        assert_true(url.startswith("https://"))

    def testApiCall(self):
        httpretty.enable()  # enable HTTPretty so that it will monkey patch the socket module
        try:
            url = "https://test.com/download"
            body = b"This is the response"
            httpretty.register_uri(httpretty.POST, url,
                               body=body)
            payload = "some unicode string"
            result = self.client.apiCall(url, payload)
            assert_equal(result, body)
            assert_not_equal(result, body.decode("ascii"))
        except:
            raise
        finally:
            httpretty.disable()
            httpretty.reset()
    def testApiCallError(self):
        httpretty.enable()  # enable HTTPretty so that it will monkey patch the socket module
        try:
            url = "https://test.com/download"
            body = b"This is the response"
            httpretty.register_uri(httpretty.POST, url, body=body, status=401)
            result = self.client.apiCall(url)
            assert_equal(result, body)
            assert_not_equal(result, body.decode("ascii"))
        except urllib.error.HTTPError:
            pass #intended
        except:
            raise
        else:
            raise Exception("a exception should have been raised during the test")
        finally:
            httpretty.disable()
            httpretty.reset()
if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
