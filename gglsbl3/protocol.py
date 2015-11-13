#!/usr/bin/env python
"""
Protocol module mainly for Python representations of objects from the google API
"""
import urllib.parse
import urllib.request
import urllib.error
import struct
import time
import random
import posixpath
import re
import hashlib
import socket
import binascii
import logging
from io import BytesIO

import gglsbl3.util
from gglsbl3 import protobuf_pb2
from gglsbl3 import MalwarePatternType_pb2
from gglsbl3.util import format_max_len

log = logging.getLogger('gglsbl3')


class BaseProtocolClient(object):
    """
    Base class FullHashProtocolClient and PrefixListProtocolClient inherit from.
    """
    def __init__(self, api_key, discard_fair_use_policy=False):
        self.config = {
            "base_url": "https://safebrowsing.google.com/safebrowsing/",
            "lists": [
                "goog-malware-shavar",
                "googpub-phish-shavar",
                "goog-unwanted-shavar"
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
        """
        Sets the timeout to be used for the next call
        """
        log.debug('Next query will be delayed %s seconds', delay)
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
        if delay < 0:
            log.error("got negative delay: '%s', will not sleep", delay)
        elif not self.discard_fair_use_policy:
            log.info('Sleeping for %s', gglsbl3.util.prettify_seconds(delay))
            time.sleep(delay)
        else:
            log.debug("didn't sleep because of settings")

    def api_call(self, url, payload=None):
        "Perform a call to Safe Browsing API"
        log.debug("performing api call to %s with payload: %s", url, payload)
        if payload is None:
            payload = b''
        if isinstance(payload, str):
            payload = bytes(payload.encode("ascii"))
        request = urllib.request.Request(url, data=BytesIO(payload),
                                         headers={'Content-Length': len(payload)})
        try:
            response = urllib.request.urlopen(request)
        except urllib.error.HTTPError:
            self._error_count += 1
            raise
        self._error_count = 0
        return response.read()

    def make_url(self, service):
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
        self._load_chunk(decoded_chunk_data)

    def _load_chunk(self, decoded_chunk_data):
        "Decode hash prefix entries"
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
        self._parse_data(raw_data)

    def _parse_data(self, data):
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

    def _unpack_chunks(self, chunkDataFH):
        "Unroll data chunk containing hash prefixes"
        # log.debug("unpacking chunk data: {data}".format(data=chunkDataFH.read()))
        decoded_chunks = []
        while True:
            packed_size = chunkDataFH.read(4)
            if len(packed_size) < 4:
                break
            size = struct.unpack(">L", packed_size)[0]
            chunk_data = chunkDataFH.read(size)
            decoded_chunk = protobuf_pb2.ChunkData()
            decoded_chunk.ParseFromString(chunk_data)
            decoded_chunks.append(decoded_chunk)
            # log.debug("sucessfully decoded chunk: %s", decoded_chunk)  # This produces way too much ouput
        log.debug("decoded %d chunks", len(decoded_chunks))
        return decoded_chunks

    def _fetchChunks(self, url):
        "Download chunks of data containing hash prefixes"
        log.debug("fetching chunk %s", format_max_len(url, max_len=45))
        response = urllib.request.urlopen(url)
        return response

    @property
    def chunks(self):
        "Generator iterating through the server respones chunk by chunk"
        log.debug("accessing chunks")
        for list_name, chunk_urls in list(self.lists_data.items()):
            for chunk_url in chunk_urls:
                log.debug("processing chunk url: %s", format_max_len(chunk_url, max_len=45))
                packed_chunks = self._fetchChunks(chunk_url)
                for chunk_data in self._unpack_chunks(packed_chunks):
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
        url = self.make_url('list')
        response = self.api_call(url)
        log.debug("got response %s", response)
        lists = [l.strip() for l in response.split()]
        return lists

    def _fetchData(self, existing_chunks):
        "Get references to data chunks containing hash prefixes"
        log.debug("chunks: %s", existing_chunks)
        self.fair_use_delay()
        url = self.make_url('downloads')
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
        response = self.api_call(url, payload)
        return response

    def _preparse_data(self, data):
        log.debug('preparsing data (length %d)', len(data))
        data = data.decode("ascii")
        data = data.split('\n')
        next_delay = data.pop(0).strip()
        if not next_delay.startswith('n:'):
            raise RuntimeError('Expected poll interval as first line, got "%s"', next_delay)
        self.set_next_call_timeout(int(next_delay[2:]))
        return data

    def retrieveMissingChunks(self, existing_chunks=None):
        """Get list of changes from the remote server

        and return them as DataResponse object
        """
        if existing_chunks is None:
            existing_chunks = {}
        log.info('Retrieving prefixes')
        log.debug('existing_chunks: %s', existing_chunks)
        raw_data = self._fetchData(existing_chunks)
        log.info("raw data length: %d", len(raw_data))
        # log.debug("got raw data: %s", str(raw_data))  # this produces way too much output!
        preparsed_data = self._preparse_data(raw_data)
        d = DataResponse(preparsed_data)
        return d


class FullHashProtocolClient(BaseProtocolClient):

    def fair_use_delay(self):
        """Throttle queries according to Request Frequency policy

        https://developers.google.com/safe-browsing/developers_guide_v3#RequestFrequency
        """
        delay = self.get_fair_use_delay()
        log.debug("preparing to sleep for %d seconds", delay)
        if delay > 0 and not self.discard_fair_use_policy:
            log.info('Sleeping for %s seconds', delay)
            time.sleep(delay)
        else:
            log.debug("didn't sleep because of settings. fair use is: %s",
                      self.discard_fair_use_policy)

    def get_fair_use_delay(self):
        if self._error_count > 1:
            delay = min(120, 30 * (2 ** (self._error_count - 2)))
        else:
            delay = self._next_call_timestamp - int(time.time())
        log.debug("delay returned is %d", delay)
        return delay

    def _parse_hash_entry(self, hash_entry):
        "Parse full-sized hash entry"
        log.debug("parsing hash entry for %s", hash_entry)
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
            log.debug("metadata strings are: %s", metadata_strings)
            #  now decode the metadata_strings with protobuf
            metadata_strings_parsed = []
            if has_metadata and metadata_strings:
                for metadata_string in metadata_strings:
                    try:
                        metadata_string_proto = MalwarePatternType_pb2.MalwarePatternType()
                        metadata_string_proto.ParseFromString(metadata_string)
                        metadata_string_parsed = metadata_string_proto.pattern_type  # pylint: disable=E1101
                        metadata_strings_parsed.append(metadata_string_parsed)
                    except Exception:
                        log.error("failed to parse metadata string: '%s'", metadata_string)
                        raise
            else:
                log.warn("hash '%s' has not metadata!", hash_entry)
            log.debug("parsed metadata strings: %s", metadata_strings_parsed)
            metadata[list_name] = metadata_strings_parsed
        return hashes, metadata

    def getHashes(self, hash_prefixes):
        "Download and parse full-sized hash entries"
        debug_prefixes = [binascii.hexlify(hash_prefix).decode("ascii") for hash_prefix in hash_prefixes]
        log.info('Downloading hashes for hash prefixes %s', debug_prefixes)
        url = self.make_url('gethash')
        prefix_len = len(hash_prefixes[0])
        hashes_len = prefix_len * len(hash_prefixes)
        p_header = '%d:%d' % (prefix_len, hashes_len)
        #  p_body = ''.join(hash_prefixes)
        p_body = b''
        for item in hash_prefixes:
            p_body += item
        payload = bytes(p_header.encode("ascii")) + b'\n' + p_body
        #  payload = '%s\n%s' % (p_header, p_body)

        response = self.api_call(url, payload)
        log.debug("response: %s", str(response))
        first_line, response = response.split(b'\n', 1)
        cache_lifetime = int(first_line.strip())
        hashes, metadata = self._parse_hash_entry(response)
        log.debug("got metadata: %s", metadata)
        return {'hashes': hashes,
                'metadata': metadata,
                'cache_lifetime': cache_lifetime
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
            """
            Undo escaping of special characters in url
            """
            uu = urllib.parse.unquote(u)
            if uu == u:
                return uu
            else:
                return full_unescape(uu)

        def quote(unsafe_string):
            """
            Returns url safe representation of input with special characters escaped
            """
            safe_chars = '!"$&\'()*+,-./:;<=>?@[\\]^_`{|}~'
            return urllib.parse.quote(unsafe_string, safe=safe_chars)
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
        _user = url_parts.username
        port = url_parts.port
        host = host.strip('.')
        host = re.sub(r'\.+', '.', host).lower()
        if host.isdigit():
            try:
                host = socket.gethostbyname(host)
            except socket.gaierror:
                pass
        if host.startswith('0x') and '.' not in host:
            try:
                host = socket.gethostbyname(host)
            except socket.gaierror:
                pass
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
            """
            Generator to get all the allowed permutations for the host part of the url
            """
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
            """
            Generator to get all the allowed permutations of the path part of the url
            """
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
        _protocol, address_str = urllib.parse.splittype(url)
        host, path = urllib.parse.splithost(address_str)
        _user, host = urllib.parse.splituser(host)
        host, _port = urllib.parse.splitport(host)
        host = host.strip('/')
        for h in url_host_permutations(host):
            for p in url_path_permutations(path):
                yield '%s%s' % (h, p)

    @staticmethod
    def digest(url):
        "Hash the URL"
        return hashlib.sha256(url.encode("ascii")).digest()
