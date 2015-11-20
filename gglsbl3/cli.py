#!/usr/bin/env python3

"""Keeps local Google Safe Browsing cache in sync.

Accessing Google Safe Browsing API requires API key, you can find
more info on getting it here:
https://developers.google.com/safe-browsing/lookup_guide#GettingStarted

"""
import sys
import time
import os
import logging

import click

from click import echo
from colorlog import ColoredFormatter

TRACE = 5
logging.addLevelName(TRACE, "TRACE")
log = logging.getLogger('gglsbl3')


import gglsbl3
from gglsbl3 import SafeBrowsingList

@click.group()
@click.version_option(gglsbl3.__version__)
@click.option('--api-key', '-k', required=True)
@click.option('--log-level')
@click.option('--log-file')
@click.option('--debug')
@click.option('--trace')
def cli(api_key, log_level, debug, trace):
    log_level = _get_log_level(log_level, debug, trace)
    _setup_logger(log_level, log_file)
    log.debug("using api key %s", api_key)

@click.command()
def sync(api_key):
    pass

@click.command()
def lookup(api_key):
    pass

def _setup_logger(log_level, log_file=None):
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(log_level)
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
    ch.setFormatter(formatter)
    log.addHandler(ch)
    log.setLevel(log_level)
    log.debug('Setting up logging with level %s', log_level)
    log.log(TRACE, 'Logger has level %s', log.getEffectiveLevel())

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
    return logging.INFO  #  this is the default

def _run_sync(sbl):
    """
    Synchronises the local database with the remote google servers.
    Takes a SafeBrowsingList Object as an argumant.
    """
    try:
        sbl.update_hash_prefix_cache()
    except (KeyboardInterrupt, SystemExit) as e:
        log.warning('Abort by user')
        sys.exit(0)
    except Exception as e:
        log.exception('Failed to synchronize with GSB service: %s', e)
        time.sleep(3)


def main():
    # FIXME: Exit more gracefully on urllib.error.URLError and other exceptions.
    # catch exceptions individually and provide info on how to fix them

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
    cli()
