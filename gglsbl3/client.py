#!/usr/bin/env python
from .protocol import PrefixListProtocolClient, FullHashProtocolClient, URL
from .storage import SqliteStorage
import logging
import binascii

log = logging.getLogger('gglsbl3')


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
        log.debug("%d existing chunks in database", len(existing_chunks))
        response = self.prefixListProtocolClient.retrieve_missing_chunks(existing_chunks=existing_chunks)
        if response.reset_required:
            log.warning("Database reset is required!")
            self.storage.total_cleanup()
        try:
            self.storage.del_add_chunks(response.del_add_chunks)
            self.storage.del_sub_chunks(response.del_sub_chunks)
            log.debug("got %d chunks in response", len(response.chunks))
            for chunk in response.chunks:
                if self.storage.chunk_exists(chunk):
                    log.debug('chunk #%d of type %s exists in stored list %s, skipping',
                              chunk.chunk_number, chunk.chunk_type, chunk.list_name)
                    continue
                self.storage.store_chunk(chunk)
        except Exception as e:
            log.error("Encountered unknown error while updating hash prefix cache (%s)", e)
            log.warning("Rolling back database because of error")
            self.storage.db.rollback()
            raise

    def _sync_full_hashes(self, hash_prefix):
        "Sync full hashes starting with hash_prefix from remote server"
        if not self.storage.full_hash_sync_required(hash_prefix):
            log.debug('Cached full hash entries are still valid for "%s", no sync required.', binascii.hexlify(hash_prefix).decode("ascii"))
            return
        full_hashes = self.fullHashProtocolClient.get_hashes([hash_prefix])
        log.debug("got full hashes: %s", full_hashes)
        if not full_hashes:
            return
        self.storage.store_full_hashes(hash_prefix, full_hashes)

    def lookup_url(self, url):
        """
        Lookup a URL in the local database.
        Returns a list of "google list names" if the URL is found in one, otherwise None
        """
        looked_up = self.lookup_url_with_metadata(url)
        if looked_up:
            return [x["list"] for x in looked_up]
        else:
            return None

    def lookup_url_with_metadata(self, url):
        """
        Lookup a URL in the local database.
        Returns a list of dictionaries containing the list name and metadata if the URL is found in one,
        otherwise None
        """
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
        log.debug('looking up "%s"', binascii.hexlify(full_hash).decode("ascii"))
        hash_prefix = full_hash[0:4]
        log.debug('looking up hash prefix "%s"', binascii.hexlify(hash_prefix).decode("ascii"))
        try:
            if self.storage.lookup_hash_prefix(hash_prefix):
                self._sync_full_hashes(hash_prefix)
                return self.storage.lookup_full_hash(full_hash)
        except:
            self.storage.db.rollback()
            raise
