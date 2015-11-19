#!/usr/bin/env python3

"""Keeps local Google Safe Browsing cache in sync.

Accessing Google Safe Browsing API requires API key, you can find
more info on getting it here:
https://developers.google.com/safe-browsing/lookup_guide#GettingStarted

"""
import argparse
import sys
import time
import os
import logging

from colorlog import ColoredFormatter

TRACE = 5
log = logging.getLogger('gglsbl3')
try:
    from gglsbl3 import SafeBrowsingList
except ImportError:  # some magic to allow usage even when gglsbl3 is not installed (i.e. in the Python Path)
    try:  # trying relative import
        print("Please install the gglsbl3 package in order for this to work properly!")
        print("trying PATH hack")
        PACKAGE_PARENT = '..'
        SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
        sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))
        # print("sys.path is now", sys.path)
        # If the following fails, then something went wrong even with the patched import! A wrong folder structure may be a cause
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
    parser.add_argument('--log-file',
                        default=None,
                        help='Path to log file, by default log to STDERR')
    parser.add_argument('--check-url',
                        default=None,
                        help='Check if URL is in black list and exit')
    parser.add_argument('--debug',
                        default=False,
                        action='store_true',
                        help='Show debug output')
    parser.add_argument('--trace',
                            default=False,
                            action='store_true',
                            help='Show vastly verbose debug output')
    parser.add_argument('--log-level',
                        help='Set log level')
    parser.add_argument('--onetime',
                        default=False,
                        action='store_true',
                        help='Run blacklists sync only once with reduced delays')
    # FIXME: add -h and --help | Edit: seems to be added by default, find a way to customise it
    # FIXME: create aliases
    return parser


def setup_logger(log_level, log_file=None):
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(log_level)
    from colorlog import ColoredFormatter

    formatter = ColoredFormatter(
            "%(log_color)s%(levelname)-8s%(reset)s %(message)s - %(filename)s:%(lineno)d",
            datefmt=None,
            reset=True,
            log_colors={
                    'TRACE': 'white,bg_purple',
                    'DEBUG':    'white,bg_cyan',
                    'INFO':     'white,bg_green',
                    'WARNING':  'white,bg_yellow',
                    'ERROR':    'white,bg_red',
                    'CRITICAL': 'red,bg_white',
            },
            secondary_log_colors={},
            style='%'
    )
    #formatter = logging.Formatter('%(levelname)s: %(message)s - %(filename)s:%(lineno)d')
    ch.setFormatter(formatter)
    log.addHandler(ch)
    logging.addLevelName(TRACE, "TRACE")
    log.setLevel(log_level)
    log.debug('Setting up logging with level %s', log_level)
    log.debug('Logger has level %s', log.getEffectiveLevel())

def _get_log_level(log_level, debug, trace):
    try:
        log_level = log_level.lower()
    except AttributeError:
        pass
    if trace or log_level in ('trace', 't'):
        return TRACE
    elif debug or log_level in ('debug', 'd'):
        return logging.DEBUG
    elif log_level in ('info', 'i'):
        return logging.INFO
    elif log_level in ('warn', 'warning', 'warnings', 'w'):
        return logging.WARNING
    elif log_level in ('error', 'e'):
        return logging.ERROR
    elif log_level in ('fatal', 'critical', 'f', 'c'):
        return logging.FATAL
    elif isinstance(log_level, int):
        return log_level
    return logging.ERROR  #  this is the default

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
        log.exception('Failed to synchronize with GSB service: %s', e)
        time.sleep(3)


def main():
    # FIXME: Exit more gracefully on urllib.error.URLError and other exceptions.
    # catch exceptions individually and provide info on how to fix them
    args_parser = setupArgsParser()
    args = args_parser.parse_args()
    log_level = _get_log_level(args.log_level, args.debug, args.trace)
    setup_logger(log_level, args.log_file)
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
