#!/usr/bin/env python
import urllib.parse
import urllib.request
import urllib.error
import struct
import time
from io import BytesIO
import random
import posixpath
import re
import hashlib
import socket
import binascii
import gglsbl3.util
from . import protobuf_pb2
from . import MalwarePatternType_pb2
from gglsbl3 import logger
log = logger.Logger("protocol").get()


class BaseProtocolClient(object):

    def __init__(self, api_key, discard_fair_use_policy=False):
        self.config = {
            "base_url": "https://safebrowsing.google.com/safebrowsing/",
            "lists": [
                "goog-malware-shavar",
                "googpub-phish-shavar"
            ],
            "url_args": {
                "key": api_key,
                "appver": "0.1",
                "pver": "3.0",
                "client": "api"
            }
        }
        self.discard_fair_use_policy = discard_fair_use_policy
        self._next_call_timestamp = 0
        self._error_count = 0

    def set_next_call_timeout(self, delay):
        log.debug('Next query will be delayed %s seconds' % delay)
        self._next_call_timestamp = int(time.time()) + delay

    def get_fair_use_delay(self):
        "Compute Server Query Delay according to Request Frequency policy"
        if self._error_count == 1:
            delay = 60
        elif self._error_count > 1:
            delay = 60 * min(480, random.randint(30, 60) * (2 ** (self._error_count - 2)))
        else:
            delay = self._next_call_timestamp - int(time.time())
        return delay

    def fair_use_delay(self):
        "Delay server query according to Request Frequency policy"
        delay = self.get_fair_use_delay()
        # FIXME: is delay > 0 check needed?
        if delay < 0:
            log.error("got negative delay: '{}', will not sleep".format(delay))
        elif not self.discard_fair_use_policy:
            log.info('Sleeping for {}'.format(gglsbl3.util.prettify_seconds(delay)))
            time.sleep(delay)
        else:
            log.debug("didn't sleep because of settings")

    def apiCall(self, url, payload=None):
        log.debug("performing api call to " + str(url) + " with payload: " + str(payload))
        #  log.debug("type url:" + str(type(url))+ " type payload: "+ str(type(payload)))
        "Perform a call to Safe Browsing API"
        if payload is None:
            payload = b''
        if type(payload) is str:
            payload = bytes(payload.encode("ascii"))
        request = urllib.request.Request(url, data=BytesIO(payload), headers={'Content-Length': len(payload)})
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError as e:
            self._error_count += 1
            raise
        self._error_count = 0
        return response.read()

    def mkUrl(self, service):
        "Generate Safe Browsing API URL"
        url = urllib.parse.urljoin(self.config['base_url'], service)
        query_params = '&'.join(['%s=%s' % (k, v) for k, v in list(self.config['url_args'].items())])
        url = '%s?%s' % (url, query_params)
        return url


class Chunk(object):

    "Represents content of Data-response chunk content"

    def __init__(self, decoded_chunk_data, list_name):
        self.list_name = list_name
        self.hashes = []
        self.chunk_number = None
        self.chunk_type = None
        self.prefix_length = None
        self._loadChunk(decoded_chunk_data)

    def _loadChunk(self, decoded_chunk_data):
        "Decode hash prefix entries"
        hash_prefixes = []
        chunk_type = 'add'
        prefix_length = 4
        if decoded_chunk_data.chunk_type == 1:
            chunk_type = 'sub'
        if decoded_chunk_data.prefix_type == 1:
            prefix_length = 32
        hashes_str = decoded_chunk_data.hashes
        hashes_count = len(hashes_str) // prefix_length
        hashes = []
        for i in range(hashes_count):
            hashes.append(hashes_str[prefix_length * i:prefix_length * (i + 1)])
        self.hashes = hashes
        self.chunk_number = decoded_chunk_data.chunk_number
        self.chunk_type = chunk_type
        self.prefix_length = prefix_length


class DataResponse(object):

    """Contains information on what changes need to be made

    to the local copy of hash prefixes list
    """

    def __init__(self, raw_data):
        self.del_add_chunks = []
        self.del_sub_chunks = []
        self.reset_required = False
        self._parseData(raw_data)

    def _parseData(self, data):
        lists_data = {}
        current_list_name = None
        for l in data:
            l = l.strip()
            if not l:
                continue
            if l.startswith('i:'):
                current_list_name = l.strip()[2:]
                lists_data[current_list_name] = []
            elif l.startswith('u:'):
                url = l[2:]
                if not url.startswith('https://'):
                    url = 'https://%s' % url
                lists_data[current_list_name].append(url)
            elif l.startswith('r:'):
                log.warn("Reset is required!")
                self.reset_required = True
            elif l.startswith('ad:'):
                chunk_id = l.split(':')[1]
                self.del_add_chunks.append(chunk_id)
            elif l.startswith('sd:'):
                chunk_id = l.split(':')[1]
                self.del_sub_chunks.append(chunk_id)
            else:
                raise RuntimeError('Response line has unexpected prefix: "{prefix}"'.format(prefix=l))
        self.lists_data = lists_data

    def _unpackChunks(self, chunkDataFH):
        "Unroll data chunk containing hash prefixes"
        # log.debug("unpacking chunk data: {data}".format(data=chunkDataFH.read()))
        decoded_chunks = []
        while True:
            log.debug("looping")
            packed_size = chunkDataFH.read(4)
            if len(packed_size) < 4:
                break
            size = struct.unpack(">L", packed_size)[0]
            chunk_data = chunkDataFH.read(size)
            decoded_chunk = protobuf_pb2.ChunkData()
            decoded_chunk.ParseFromString(chunk_data)
            decoded_chunks.append(decoded_chunk)
            log.debug("sucessfully decoded chunk: {chunk}".format(chunk=decoded_chunk))
        log.debug("decoded chunks: {chunks}".format(chunks=decoded_chunks))
        return decoded_chunks

    def _fetchChunks(self, url):
        "Download chunks of data containing hash prefixes"
        log.debug("fetching chunk {url}".format(url=url))
        response = urllib.request.urlopen(url)
        log.debug("got response: {res}".format(res=response))
        # readresponse = response.read()
        # log.debug("got response: {res}".format(res=readresponse))
        # log.debug("got response status: {status}".format(status=response.status))
        return response

    @property
    def chunks(self):
        "Generator iterating through the server respones chunk by chunk"
        log.debug("accessing chunks")
        for list_name, chunk_urls in list(self.lists_data.items()):
            log.debug(str(list_name)+str(chunk_urls))
            for chunk_url in chunk_urls:
                log.debug("processing {url}".format(url = chunk_url))
                packed_chunks = self._fetchChunks(chunk_url)
                log.debug("packed chunks: {chunks}".format(chunks=packed_chunks))
                for chunk_data in self._unpackChunks(packed_chunks):
                    # log.debug("chunk_data: {data}".format(data=chunk_data))
                    chunk = Chunk(chunk_data, list_name)
                    # log.debug("yielding {chunk}".format(chunk=chunk))
                    yield chunk


class PrefixListProtocolClient(BaseProtocolClient):

    def __init__(self, api_key, discard_fair_use_policy=False):
        super(PrefixListProtocolClient, self).__init__(api_key, discard_fair_use_policy)
        self.set_next_call_timeout(random.randint(0, 300))

    def getLists(self):
        "Get available black/white lists"
        log.info('Fetching available lists')
        url = self.mkUrl('list')
        response = self.apiCall(url)
        log.debug("got response" + str(response))
        lists = [l.strip() for l in response.split()]
        return lists

    def _fetchData(self, existing_chunks):
        log.debug("chunks: " + str(existing_chunks))
        "Get references to data chunks containing hash prefixes"
        self.fair_use_delay()
        url = self.mkUrl('downloads')
        payload = []
        for l in self.config['lists']:
            list_data = existing_chunks.get(l, {})
            if not list_data:
                payload.append('%s;' % l)
                continue
            list_data_cmp = []
            if 'add' in list_data:
                list_data_cmp.append('a:%s' % list_data['add'])
            if 'sub' in list_data:
                list_data_cmp.append('s:%s' % list_data['sub'])
            payload.append('%s;%s' % (l, ':'.join(list_data_cmp)))
        payload = '\n'.join(payload) + '\n'
        response = self.apiCall(url, payload)
        return response

    def _preparseData(self, data):
        log.debug("preparsing data: "+str(data))
        data = data.decode("ascii")
        data = data.split('\n')
        next_delay = data.pop(0).strip()
        if not next_delay.startswith('n:'):
            raise RuntimeError('Expected poll interval as first line, got "%s"', next_delay)
        self.set_next_call_timeout(int(next_delay[2:]))
        return data

    def retrieveMissingChunks(self, existing_chunks={}):
        """Get list of changes from the remote server

        and return them as DataResponse object
        """
        log.info('Retrieving prefixes')
        log.debug('existing_chunks: {chunks}'.format(chunks=existing_chunks))
        raw_data = self._fetchData(existing_chunks)
        log.info("raw data length: {}".format(len(raw_data)))
        log.debug("got raw data: " + str(raw_data))
        preparsed_data = self._preparseData(raw_data)
        d = DataResponse(preparsed_data)
        return d


class FullHashProtocolClient(BaseProtocolClient):

    def fair_use_delay(self):
        """Throttle queries according to Request Frequency policy

        https://developers.google.com/safe-browsing/developers_guide_v3#RequestFrequency
        """
        delay = self.get_fair_use_delay()
        log.debug("preparing to sleep for "+str(delay)+" seconds")
        if delay > 0 and not self.discard_fair_use_policy:
            log.info('Sleeping for %s seconds' % delay)
            time.sleep(delay)
        else:
            log.debug("didn't sleep because of settings. fair use is: " + str(self.discard_fair_use_policy))

    def get_fair_use_delay(self):
        if self._error_count > 1:
            delay = min(120, 30 * (2 ** (self._error_count - 2)))
        else:
            delay = self._next_call_timestamp - int(time.time())
        log.debug("delay returned is " + str(delay))
        return delay

    def _parseHashEntry(self, hash_entry):
        "Parse full-sized hash entry"
        log.debug("parsing hash entry for {hash_entry}".format(hash_entry=hash_entry))
        hashes = {}
        metadata = {}
        while True:
            if not hash_entry:
                break
            has_metadata = False
            header, hash_entry = hash_entry.split(b'\n', 1)
            opts = header.split(b':')
            if len(opts) == 4:
                if opts[3] == b'm':
                    has_metadata = True
                else:
                    raise RuntimeError('Failed to parse full hash entry header "%s"' % header)
            list_name = opts[0]
            entry_len = int(opts[1])
            entry_count = int(opts[2])
            hash_strings = []
            metadata_strings = []
            for i in range(entry_count):
                hash_string = hash_entry[entry_len * i:entry_len * (i + 1)]
                hash_strings.append(hash_string)
            hash_entry = hash_entry[entry_count * entry_len:]
            if has_metadata:
                for i in range(entry_count):
                    next_metadata_len, hash_entry = hash_entry.split(b'\n', 1)
                    next_metadata_len = int(next_metadata_len)
                    metadata_str = hash_entry[:next_metadata_len]
                    metadata_strings.append(metadata_str)
                    hash_entry = hash_entry[next_metadata_len:]
            elif hash_entry:
                raise RuntimeError('Hash length does not match header declaration (no metadata)')
            hashes[list_name] = hash_strings
            log.debug("metadata strings are: {metadata_strings}".format(metadata_strings=metadata_strings))
            #  now decode the metadata_strings with protobuf
            metadata_strings_parsed = []
            if has_metadata and metadata_strings:
                for metadata_string in metadata_strings:
                    try:
                        metadata_string_proto = MalwarePatternType_pb2.MalwarePatternType()
                        metadata_string_proto.ParseFromString(metadata_string)
                        metadata_string_parsed = metadata_string_proto.pattern_type
                        metadata_strings_parsed.append(metadata_string_parsed)
                    except Exception:
                        log.error("failed to parse metadata string: '{metadata_string}'".format(metadata_string=metadata_string))
                        raise
            else:
                log.warn("hash '{hash_entry}' has not metadata!".format(hash_entry=hash_entry))
            log.debug("parsed metadata strings: {metadata_strings_parsed}".format(metadata_strings_parsed=metadata_strings_parsed))
            metadata[list_name] = metadata_strings_parsed
        return hashes, metadata

    def getHashes(self, hash_prefixes):
        "Download and parse full-sized hash entries"
#         for hash_prefix in hash_prefixes:
#             log.debug("hash prefix: {}".format(hash_prefix))
#             log.debug(binascii.hexlify(hash_prefix))
#             log.debug(binascii.hexlify(hash_prefix).decode("ascii"))
        debug_prefixes = [binascii.hexlify(hash_prefix).decode("ascii") for hash_prefix in hash_prefixes]
        log.info('Downloading hashes for hash prefixes {prefixes}'.format(prefixes=debug_prefixes))
        url = self.mkUrl('gethash')
        prefix_len = len(hash_prefixes[0])
        hashes_len = prefix_len * len(hash_prefixes)
        p_header = '%d:%d' % (prefix_len, hashes_len)
        #  p_body = ''.join(hash_prefixes)
        p_body = b''
        for item in hash_prefixes:
            p_body += item
        payload = bytes(p_header.encode("ascii")) + b'\n' + p_body
        #  payload = '%s\n%s' % (p_header, p_body)

        response = self.apiCall(url, payload)
        log.debug("response: " + str(response))
        first_line, response = response.split(b'\n', 1)
        cache_lifetime = int(first_line.strip())
        hashes, metadata = self._parseHashEntry(response)
        log.debug("got metadata: {metadata}".format(metadata=metadata))
        return {'hashes': hashes,
                'metadata': metadata,
                'cache_lifetime': cache_lifetime,
                }


class URL(object):

    "URL representation suitable for lookup"

    def __init__(self, url):
        self.url = str(url)

    @property
    def hashes(self):
        "Hashes of all possible permutations of the URL in canonical form"
        for url_variant in self.url_permutations(self.canonical):
            url_hash = self.digest(url_variant)
            yield url_hash

    @property
    def canonical(self):
        "Convert URL to its canonical form"
        def full_unescape(u):
            uu = urllib.parse.unquote(u)
            if uu == u:
                return uu
            else:
                return full_unescape(uu)

        def quote(s):
            safe_chars = '!"$&\'()*+,-./:;<=>?@[\\]^_`{|}~'
            return urllib.parse.quote(s, safe=safe_chars)
        url = self.url.strip()
        url = url.replace('\n', '').replace('\r', '').replace('\t', '')
        url = url.split('#', 1)[0]
        url = quote(full_unescape(url))
        url_parts = urllib.parse.urlsplit(url)
        if not url_parts[0]:
            url = 'http://%s' % url
            url_parts = urllib.parse.urlsplit(url)
        protocol = url_parts.scheme
        host = full_unescape(url_parts.hostname)
        path = full_unescape(url_parts.path)
        query = url_parts.query
        if not query and '?' not in url:
            query = None
        if not path:
            path = '/'
        has_trailing_slash = (path[-1] == '/')
        path = posixpath.normpath(path).replace('//', '/')
        if has_trailing_slash and path[-1] != '/':
            path = path + '/'
        user = url_parts.username
        port = url_parts.port
        host = host.strip('.')
        host = re.sub(r'\.+', '.', host).lower()
        if host.isdigit():
            host = socket.gethostbyname(host)
        if host.startswith('0x') and '.' not in host:
            host = socket.gethostbyname(host)
        if path == '':
            path = '/'
        quoted_path = quote(path)
        quoted_host = quote(host)
        if port is not None:
            quoted_host = '%s:%s' % (quoted_host, port)
        canonical_url = '%s://%s%s' % (protocol, quoted_host, quoted_path)
        if query is not None:
            canonical_url = '%s?%s' % (canonical_url, query)
        return canonical_url

    # FIXME: move these to own module and out of class
    @staticmethod
    def url_permutations(url):
        """Try all permutations of hostname and path which can be applied
        to blacklisted URLs"""
        def url_host_permutations(host):
            if re.match(r'\d+\.\d+\.\d+\.\d+', host):
                yield host
                return
            parts = host.split('.')
            l = min(len(parts), 5)
            if l > 4:
                yield host
            for i in range(l - 1):
                yield '.'.join(parts[i - l:])

        def url_path_permutations(path):
            if path != '/':
                yield path
            query = None
            if '?' in path:
                path, query = path.split('?', 1)
            if query is not None:
                yield path
            path_parts = path.split('/')[0:-1]
            curr_path = ''
            for i in range(min(4, len(path_parts))):
                curr_path = curr_path + path_parts[i] + '/'
                yield curr_path
        protocol, address_str = urllib.parse.splittype(url)
        host, path = urllib.parse.splithost(address_str)
        user, host = urllib.parse.splituser(host)
        host, port = urllib.parse.splitport(host)
        host = host.strip('/')
        for h in url_host_permutations(host):
            for p in url_path_permutations(path):
                yield '%s%s' % (h, p)

    # FXIME: todo
    @staticmethod
    def digest(url):
        "Hash the URL"
        return hashlib.sha256(url.encode("ascii")).digest()
