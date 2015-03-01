'''
Created on Feb 18, 2015

@author: SK
'''
import unittest
import urllib
from gglsbl3 import protocol
import time
import httpretty
from nose.tools import *
from tests import logger
log = logger.Logger("protocoltest").get()


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
            pass  # intended
        except:
            raise
        else:
            raise Exception("a exception should have been raised during the test")
        finally:
            httpretty.disable()
            httpretty.reset()


class FullHashProtocolTest(unittest.TestCase):

    def setUp(self):
        self.api_key = "abcdefg"
        self.client = protocol.FullHashProtocolClient(self.api_key)

    def tearDown(self):
        pass

    def testSetNextCallTimeOut(self, delay=30):
        self.client.set_next_call_timeout(delay)
        # log.debug("next call timestamp is: "+ str(self.client._next_call_timestamp))
        assert_equal(self.client._next_call_timestamp, int(time.time()) + delay)

    def testFullHashClient(self):
        res = self.client._parseHashEntry(b'goog-malware-shavar:32:1:m\n$\xb2A\x91\xaf\xc2\xd5\x8b\xdfh\xc8R\x82Y\x9do\xbb\x84\x92\xf9\xa2h,\x02\xf4j\x8dQy\x1e\r\xff2\n\x08\x02')
        assert_equal(len(res), 2)

    def testGetFairUseDelay(self):
        self.testSetNextCallTimeOut(10)
        delay = self.client.get_fair_use_delay()
        assert_in(delay, [9, 10])

    def testGetFairUseDelayWithError(self):
        self.client._error_count = 1
        self.testSetNextCallTimeOut(10)
        delay = self.client.get_fair_use_delay()
        assert_in(delay, [9, 10])
        self.client._error_count = 2
        log.debug("delay is: " + str(self.client.get_fair_use_delay()))
        assert_less_equal(self.client.get_fair_use_delay(), 120)
        assert_greater_equal(self.client.get_fair_use_delay(), 30)
        self.client._error_count = 20
        assert_equal(self.client.get_fair_use_delay(), 120)

    def testFairUseDelay(self):
        self.client.set_next_call_timeout(2)
        time1 = time.time()
        log.debug("sleeping!")
        self.client.fair_use_delay()
        time2 = time.time()
        delta = time2 - time1
        assert_equal(int(round(delta)), 2)


class URLTest(unittest.TestCase):

    def setUp(self):
        self.api_key = "abcdefg"
        self.url = "http://fromopics.com/some/thing.html?a=b#hash"
        self.URLObject = protocol.URL(self.url)

    def testDigest(self):
        assert_equal(type(self.URLObject.digest(self.url)), bytes)

    def testPermutations(self):
        permutations = []
        for item in self.URLObject.url_permutations(self.url):
            permutations.append(item)
        assert_equal(len(permutations), 4)


class PrefixListProtocolTest(unittest.TestCase):

    def setUp(self):
        self.api_key = "abcdefg"
        self.client = protocol.PrefixListProtocolClient(self.api_key)

    def testGetLists(self):
        httpretty.enable()  # enable HTTPretty so that it will monkey patch the socket module
        try:
            url = "https://safebrowsing.google.com/safebrowsing/list?client=api&key=abcdefg&pver=3.0&appver=0.1"
            body = b"goog-malware-shavar\ngoog-regtest-shavar\ngoog-whitedomain-shavar\ngoogpub-phish-shavar\n"
            httpretty.register_uri(httpretty.POST, url, body=body)
            response = self.client.getLists()
            assert_equal(len(response), 4)
            assert_in(b'goog-malware-shavar', response)
            assert_in(b'goog-regtest-shavar', response)
            assert_in(b'goog-whitedomain-shavar', response)
            assert_in(b'googpub-phish-shavar', response)
        except Exception:
            raise
        finally:
            httpretty.disable()
            httpretty.reset()


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
    # test = PrefixListProtocolTest()
    # test.setUp()
    # test.testGetLists()