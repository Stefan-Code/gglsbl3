#!/usr/bin/env python2.7

"""Keeps local Google Safe Browsing cache in sync.

Accessing Google Safe Browsing API requires API key, you can find
more info on getting it here:
https://developers.google.com/safe-browsing/lookup_guide#GettingStarted

"""
import argparse
import json  # FIXME: Needed?
import sys
import time
import os
import logging
log = logging.getLogger()
log.setLevel(logging.DEBUG)
try:
    from gglsbl3 import SafeBrowsingList
except ImportError:  # some magic to allow usage even when gglsbl3 is not installed (i.e. in the Python Path)
    try:  # trying relative import
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))
        # If the following fails, then something went wrong even with the relative import! A wrong folder structure may be a cause
        from gglsbl3 import SafeBrowsingList
    except ImportError:
        raise ImportError("Seems like gglsbl3 is not installed (or not in the right Folder or you are missing dependencies)")


def setupArgsParser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-key',
                        default=None,
                        required=True,
                        help='Safe Browsing API key [REQUIRED]')
    parser.add_argument('--db-path',
                        default='./gsb_v3.db',
                        help='Path to SQLite DB')
    parser.add_argument('--log',
                        default=None,
                        help='Path to log file, by default log to STDERR')
    parser.add_argument('--check-url',
                        default=None,
                        help='Check if URL is in black list and exit')
    parser.add_argument('--debug',
                        default=False,
                        action='store_true',
                        help='Show debug output')
    parser.add_argument('--onetime',
                        default=False,
                        action='store_true',
                        help='Run blacklists sync only once with reduced delays')
    # FXIME: add -h and --help | Edit: seems to be added by default, find a way to customise it
    # FIXME: create aliases
    return parser

# FIXME: move logging stuff to here. Beware of the scope
def setupLogger(log_file, debug):
    pass


def run_sync(sbl):
    """
    Synchronises the local database with the remote google servers.
    Takes a SafeBrowsingList Object as an argumant.
    """
    try:
        sbl.update_hash_prefix_cache()
    except (KeyboardInterrupt, SystemExit) as e:
        log.info('Shutting down')
        sys.exit(0)
    except Exception as e:
        log.exception('Failed to synchronize with GSB service: {}'.format(e))
        time.sleep(3)


def main():
    # FIXME: Exit more gracefully on urllib.error.URLError and other exceptions.
    # catch exceptions individually and provide info on how to fix them
    args_parser = setupArgsParser()
    args = args_parser.parse_args()
    setupLogger(args.log, args.debug)
    # FIXME: Sync before lookup?
    if args.check_url:
        # FIXME: check for validity of API KEY, e.g. min-length
        sbl = SafeBrowsingList(args.api_key, db_path=args.db_path)
        bl = sbl.lookup_url(args.check_url)
        if bl is None:
            print('%s is not blacklisted' % args.check_url)
        else:
            print('%s is blacklisted in %s' % (args.check_url, bl))
        sys.exit(0)
    if args.onetime:
        sbl = SafeBrowsingList(args.api_key, db_path=args.db_path, discard_fair_use_policy=True)
        run_sync(sbl)
    else:
        sbl = SafeBrowsingList(args.api_key, db_path=args.db_path)
        while True:
            run_sync(sbl)

if __name__ == '__main__':
    main()
