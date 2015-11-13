'''
Created on Feb 18, 2015

@author: SK
'''
import unittest
import urllib
import logging
import time
import httpretty

from gglsbl3 import protocol
from nose.tools import *
log = logging.getLogger('gglsbl3')


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

    def testDiscardFairUse(self):
        client = protocol.BaseProtocolClient(api_key=self.api_key, discard_fair_use_policy=True)
        client.set_next_call_timeout(2)
        time1 = time.time()
        client.fair_use_delay()
        time2 = time.time()
        delta = time2 - time1
        assert_equal(int(round(delta)), 0)

    def test_make_url(self):
        url = self.client.make_url("downloads")
        assert_true(url.startswith("https://"))

    def test_api_call(self):
        httpretty.enable()  # enable HTTPretty so that it will monkey patch the socket module
        try:
            url = "https://test.com/download"
            body = b"This is the response"
            httpretty.register_uri(httpretty.POST, url,
                                   body=body)
            payload = "some unicode string"
            result = self.client.api_call(url, payload)
            assert_equal(result, body)
            assert_not_equal(result, body.decode("ascii"))
        except:
            raise
        finally:
            httpretty.disable()
            httpretty.reset()

    def test_api_call_rror(self):
        httpretty.enable()  # enable HTTPretty so that it will monkey patch the socket module
        try:
            url = "https://test.com/download"
            body = b"This is the response"
            httpretty.register_uri(httpretty.POST, url, body=body, status=401)
            result = self.client.api_call(url)
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
        self.api_key = "abcdef"
        self.client = protocol.FullHashProtocolClient(self.api_key)

    def tearDown(self):
        pass

    def testSetNextCallTimeOut(self, delay=30):
        self.client.set_next_call_timeout(delay)
        # log.debug("next call timestamp is: "+ str(self.client._next_call_timestamp))
        assert_equal(self.client._next_call_timestamp, int(time.time()) + delay)

    def testGetHashes(self):
        httpretty.enable()  # enable HTTPretty so that it will monkey patch the socket module
        try:
            url = "https://safebrowsing.google.com/safebrowsing/gethash"
            hash_prefix = bytes(bytearray.fromhex('24b24191'))
            body = b'600\ngoog-malware-shavar:32:1:m\n$\xb2A\x91\xaf\xc2\xd5\x8b\xdfh\xc8R\x82Y\x9do\xbb\x84\x92\xf9\xa2h,\x02\xf4j\x8dQy\x1e\r\xff2\n\x08\x02'
            httpretty.register_uri(httpretty.POST, url, body=body)
            result = self.client.getHashes([hash_prefix])
            log.info("got result: {res}".format(res=result))
            # log.debug(httpretty.last_request())
            # log.debug(dir(httpretty.last_request()))
            expected = {'hashes': {b'goog-malware-shavar': [b'$\xb2A\x91\xaf\xc2\xd5\x8b\xdfh\xc8R\x82Y\x9do\xbb\x84\x92\xf9\xa2h,\x02\xf4j\x8dQy\x1e\r\xff']}, 'cache_lifetime': 600, 'metadata': {b'goog-malware-shavar': [2]}} # integer is returned now as metadata instead of unparsed protobuf bytes
            assert_equal(result, expected)
        except:
            raise
        finally:
            httpretty.disable()
            httpretty.reset()

    def testFullHashClient(self):
        res = self.client._parse_hash_entry(b'goog-malware-shavar:32:1:m\n$\xb2A\x91\xaf\xc2\xd5\x8b\xdfh\xc8R\x82Y\x9do\xbb\x84\x92\xf9\xa2h,\x02\xf4j\x8dQy\x1e\r\xff2\n\x08\x02')
        assert_equal(len(res), 2)

    def testGetFairUseDelay(self):
        self.testSetNextCallTimeOut(10)
        delay = self.client.get_fair_use_delay()
        assert_in(delay, [9, 10])

    def testDiscardFairUse(self):
        client = protocol.FullHashProtocolClient(api_key=self.api_key, discard_fair_use_policy=True)
        client.set_next_call_timeout(2)
        time1 = time.time()
        client.fair_use_delay()
        time2 = time.time()
        delta = time2 - time1
        assert_equal(int(round(delta)), 0)

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
        self.url = "http://google.com/some/thing.html?a=b#hash"
        self.URLObject = protocol.URL(self.url)

    def testDigest(self):
        assert_equal(type(self.URLObject.digest(self.url)), bytes)

    def testPermutations(self):
        permutations = []
        for item in self.URLObject.url_permutations(self.url):
            permutations.append(item)
        assert_equal(len(permutations), 4)

    def testHashes(self):
        hashes = []
        for hash_ in self.URLObject.hashes:
            hashes.append(hash_)
        assert_equal(len(hashes), 4)

    def testBare(self):
        url = "google.com"
        URLObject = protocol.URL(self.url)

class PrefixListProtocolTest(unittest.TestCase):

    def setUp(self):
        self.api_key = "abcdefg"
        self.client = protocol.PrefixListProtocolClient(self.api_key, discard_fair_use_policy=True)  # discard fair use as we are mocking http and dont wanna wait forever for the test to finish...

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

    def testRetrieveMissingChunks(self):
        httpretty.enable()  # enable HTTPretty so that it will monkey patch the socket module
        try:
            existing_chunks = {'goog-malware-shavar': {'add': '160929-173975', 'sub': '151695-152051,152053-153220,153222-154217,154219-154240,154242-154260,154262-154638,154640-155042,155044-155415,155417-155505,155507-155706,155708-155768,155770-155781,155783-157480,157482-157623,157625-157836,157838-159256,159258-160279,160281-160909,160911-165040'}, 'googpub-phish-shavar': {'add': '325243-336324', 'sub': '20232-20239,20241-20251,20253-20254,20257-20258,20262-20264,20266,20268-20269,20272-20273,20275,20277-20278,20280,20282-20284,20286-20291,20293-20297,20300,20302-20309,20311,20314-20320,20322-20324,20326,20328-20330,20332-20333,20335-20336,20339-20341,20343-20344,20347,20349-20352,20354-20356,20358-20359,20361-20364,20366,20368-20375,20377-20378,20380-20381,20383-20384,20386-20396,20399-20404,20407-20411,20413-20416,20418-20429,20431-20438,20442-20459,20462-20479,20481-20490,20492-20494,20496-20500,20502-20506,20509,20511-20521,20523-20531,20533-20583,20585-20591,20593-20613,20615-20647,20649-20900,20902-20947,20949-20991,20993-21052,21054,21056-21176'}}
            url = "https://safebrowsing.google.com/safebrowsing/downloads"
            body = b'n:1704\ni:goog-malware-shavar\nu:safebrowsing-cache.google.com/safebrowsing/rd/ChNnb29nLW1hbHdhcmUtc2hhdmFyOAFAAkoMCAEQsYkKGLGJCiABSgwIABCYzwoYmM8KIAE\ni:googpub-phish-shavar\nu:safebrowsing-cache.google.com/safebrowsing/rd/ChRnb29ncHViLXBoaXNoLXNoYXZhcjgBQAJKDAgAEMXDFBjFwxQgAQ\n'
            httpretty.register_uri(httpretty.POST, url, body=body, status=200)

            mockchunks = [{"url": "https://safebrowsing-cache.google.com/safebrowsing/rd/ChNnb29nLW1hbHdhcmUtc2hhdmFyOAFAAkoMCAEQsYkKGLGJCiABSgwIABCYzwoYmM8KIAE", "body": b'\x00\x00\x004\x08\xb1\x89\n\x10\x01"\x18\xcc\xbdS\xfa:\xb7\x1d\xa3\xd1R&\xde\xca\x1a\x92\xfb\x84Wy\x7fI5\xba\xe0*\x12\x97\xcd\n\xec\x8f\n\xf5\x9a\n\xe3\xf8\t\xc8\xfe\t\xb9\xb6\n\x00\x00\x00\x0e\x08\x98\xcf\n"\x08\xca\x8eoj$\x19ro'},
                      {"url": "https://safebrowsing-cache.google.com/safebrowsing/rd/ChRnb29ncHViLXBoaXNoLXNoYXZhcjgBQAJKDAgAEMXDFBjFwxQgAQ", "body": b'\x00\x00\x00Z\x08\xc5\xc3\x14"T\xa3p\xda\x91l\xa9\xa5\xa89SOl\x12,\x0bXB0\xed\x1f\x114b2\xf2\x8b\x9a\xeb\xf4\xb6\xc1f\xe6\x80!\x81\xdd\xc4\xb5O\xfa\xfdKS\x03<\x97\xfb\x83\xb6\r\xfa\xfe\x15$\xa0\xa7C\xd4W\xd8\x029\xad\x03\xf9r\x0c/d\xb8jz\xc6\xaf4qQ\xccQ/1\xb3\xc3'}
                      ]
            for mockchunk in mockchunks:
                log.debug("adding url {url} and body {body}".format(url=mockchunk['url'][:10], body=mockchunk['body'][:10]))
                httpretty.register_uri(httpretty.POST, mockchunk['url'], body=mockchunk['body'], status=200)
                httpretty.register_uri(httpretty.GET, mockchunk['url'], body=mockchunk['body'], status=200)
            response = self.client.retrieveMissingChunks(existing_chunks)
            log.debug("RESPONSE: {res}".format(res=response))
            log.debug("chunks: {res}".format(res=response.chunks))
            chunks = []
            for chunk in response.chunks:
                log.debug("--- CHUNK --- {chunktype} {chunk}".format(chunktype=chunk.chunk_type, chunk=chunk.chunk_number))
                chunks.append({"number": chunk.chunk_number, "type": chunk.chunk_type})
            assert_in({'type': 'add', 'number': 336325}, chunks)
            assert_in({'type': 'sub', 'number': 165041}, chunks)
            assert_in({'type': 'add', 'number': 173976}, chunks)
            log.info("got chunks: {chunks}".format(chunks=chunks))
            log.debug("response: {res}".format(res=response))
        except Exception:
            raise
        finally:
            httpretty.disable()
            httpretty.reset()

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
    # test = URLTest()
    # test.setUp()
    # test.testHashes()
