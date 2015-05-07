#!/usr/bin/env python
from .protocol import PrefixListProtocolClient, FullHashProtocolClient, URL
from .storage import SqliteStorage
from . import logger
import binascii

log = logger.Logger("client").get()


class SafeBrowsingList(object):
    """Interface for Google Safe Browsing API

    supporting partial update of the local cache.
    https://developers.google.com/safe-browsing/developers_guide_v3
    """

    def __init__(self, api_key, db_path='./gsb_v3.db', discard_fair_use_policy=False):
        # FIXME: missing docstring
        self.prefixListProtocolClient = PrefixListProtocolClient(api_key, discard_fair_use_policy=discard_fair_use_policy)
        self.fullHashProtocolClient = FullHashProtocolClient(api_key)
        self.storage = SqliteStorage(db_path)

    def _close_storage(self):
        """
        Close the connection to the database
        """
        self.storage.close()

    # FIXME: return True if there was something to update, return False if local database is in sync
    def update_hash_prefix_cache(self):
        "Sync locally stored hash prefixes with remote server"
        existing_chunks = self.storage.get_existing_chunks()
        response = self.prefixListProtocolClient.retrieveMissingChunks(existing_chunks=existing_chunks)
        if response.reset_required:
            self.storage.total_cleanup()
        try:
            self.storage.del_add_chunks(response.del_add_chunks)
            self.storage.del_sub_chunks(response.del_sub_chunks)
            for chunk in response.chunks:
                if self.storage.chunk_exists(chunk):
                    log.debug('chunk #%d of type %s exists in stored list %s, skipping',
                              chunk.chunk_number, chunk.chunk_type, chunk.list_name)
                    continue
                self.storage.store_chunk(chunk)
        except:
            self.storage.db.rollback()
            raise

    def _sync_full_hashes(self, hash_prefix):
        "Sync full hashes starting with hash_prefix from remote server"
        if not self.storage.full_hash_sync_required(hash_prefix):
            log.debug('Cached full hash entries are still valid for "{hex}", no sync required.'.format(hex=binascii.hexlify(hash_prefix).decode("ascii")))
            return
        full_hashes = self.fullHashProtocolClient.getHashes([hash_prefix])
        log.debug("got full hashes: {full_hashes}".format(full_hashes=full_hashes))
        if not full_hashes:
            return
        self.storage.store_full_hashes(hash_prefix, full_hashes)

    def lookup_url(self, url):
        # FIXME: Missing docstring
        # The following fails if the list is empty
        # return [x["list"] for x in self.lookup_url_with_metadata(url)]  # this retains backwards compability with clients not expecting the dictionary that includes metadata
        looked_up = self.lookup_url_with_metadata(url)
        if looked_up:
            return [x["list"] for x in looked_up]
        else:
            return None
        
    def lookup_url_with_metadata(self, url):
        "Look up URL in Safe Browsing blacklists"
        url_hashes = URL(url).hashes
        # log.debug(url_hashes)
        for url_hash in url_hashes:
            list_name = self._lookup_hash(url_hash)
            if list_name:
                return list_name
        return None

    def _lookup_hash(self, full_hash):
        """Lookup URL hash in blacklists

        Returns names of lists it was found in.
        """
        log.debug('looking up "{full_hash}"'.format(full_hash=binascii.hexlify(full_hash).decode("ascii")))
        hash_prefix = full_hash[0:4]
        try:
            if self.storage.lookup_hash_prefix(hash_prefix):
                self._sync_full_hashes(hash_prefix)
                return self.storage.lookup_full_hash(full_hash)
        except:
            self.storage.db.rollback()
            raise
