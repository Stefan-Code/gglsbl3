#!/usr/bin/env python3

"""Keeps local Google Safe Browsing cache in sync.

Accessing Google Safe Browsing API requires API key, you can find
more info on getting it here:
https://developers.google.com/safe-browsing/lookup_guide#GettingStarted

"""
import sys
import time
import logging
import urllib
import threading
import os

import click

from click import echo
from colorlog import ColoredFormatter

TRACE = 5
logging.addLevelName(TRACE, "TRACE")  # TODO: move this to package __init__.py ?
log = logging.getLogger('gglsbl3')


import gglsbl3
from gglsbl3 import SafeBrowsingList

class SafeBrowsingListCli:
    """
    Object to store the SafeBrowsingList instance and the configuration
    supplied in the cli.
    """
    def __init__(self, sbl, config):
        self.sbl = sbl
        self.config = config

pass_sbl = click.make_pass_decorator(SafeBrowsingListCli)
SAFE = click.style("[ SAFE ]", bold=True, bg='green', fg='white')
UNSAFE = click.style("[UNSAFE]", bold=True, bg='red', fg='white')

@click.group()
@click.version_option(gglsbl3.__version__)
@click.option('--api-key', '-k', envvar='GGLSBL3_API_KEY',
              required=True, metavar='API_KEY', help='Your google safe browsing v3 API key')
@click.option('--db-file', type=click.Path(file_okay=True),
              default='./gsb_v3.db',
              help='The path to the sqlite database file tp use. (including the filename)')
@click.option('--no-fair-use', is_flag=True,
              help='Disable the fair use policiy. Do not wait between requests.')
@click.option('--log-level',
              type=click.Choice(['trace', 'debug', 'info', 'warning', 'error', 'critical']),
              default='info'
              )
@click.option('--log-file',
              type=click.Path(file_okay=True), help='file to write logging messages to')
@click.option('--log-file-level',
              type=click.Choice(['trace', 'debug', 'info', 'warning', 'error', 'critical']))
@click.option('--debug', is_flag=True)
@click.option('--trace', is_flag=True)
@click.option('--dev', is_flag=True)
@click.option('--silent', '-s', is_flag=True)
@click.pass_context
def cli(ctx, *args, **kwargs):
    log_level = _get_log_level(kwargs['log_level'], debug=kwargs['debug'], trace=kwargs['trace'])
    _setup_logger(log_level, kwargs['log_file'], kwargs['silent'])
    log.debug("using api key %s", kwargs['api_key'])
    sbl = SafeBrowsingList(kwargs['api_key'], kwargs['db_file'], discard_fair_use_policy=kwargs['no_fair_use'])
    ctx.obj = SafeBrowsingListCli(sbl, kwargs)

@cli.command()
@click.pass_context
@click.option('--exit-when-synced', is_flag=True)
def sync(ctx, *args, **kwargs):
    echo("syncing...")
    _run_sync(ctx.obj.sbl)

@cli.command()
@click.pass_context
def update(ctx):
    echo("running update...")
    _run_sync(ctx.obj.sbl, loop=False)

@cli.command()
@click.argument('url', required=True)
@click.pass_context
def lookup(ctx, url):
    """
    Look up a URL in the safebrowsing database
    """
    blacklisted = ctx.obj.sbl.lookup_url_with_metadata(url)
    malware_type = 3  # 3 is the default return code if no metadata available but the url is listed
    if blacklisted is None:
        info = click.style('NOT blacklisted', bold=True, bg='green', fg='white')
        echo('{safe} {url} is {info}'.format(safe=SAFE, url=url, info=info))
        malware_type = 0  # 0 means url OK
    else:
        malware_type = min([item['metadata'] for item in blacklisted if item['metadata'] != 0])
        for list_name in blacklisted:
            info = click.style('BLACKLISTED', bold=True, bg='red', fg='white')
            echo('{unsafe} {url} is {info} in {list_name}'.format(unsafe=UNSAFE, url=url, info=info, list_name=list_name))
    sys.exit(malware_type)

@cli.command()
@click.option('--yes', '-y', is_flag=True)
@click.pass_context
def purge(ctx, yes):
    db_file = os.path.abspath(ctx.obj.config['db_file'])
    if not yes:
        confirmed = click.confirm("Are you sure you want to remove {}".format(db_file))
    else:
        confirmed = True
    if confirmed:
        #raise Exception("Not implemented")
        #ctx.obj.sbl.storage.total_cleanup()  # cleaned database still uses a lot of disk space
        try:
            echo('removing {}'.format(db_file))
            os.remove(db_file)
        except:
            raise
        echo('done.')
    else:
        echo("aborting.")

@cli.command()
@click.pass_context
def stat(ctx):
    chunks = ctx.obj.sbl.storage.get_num_chunks()
    hash_prefixes = ctx.obj.sbl.storage.get_num_hash_prefixes()
    full_hashes = ctx.obj.sbl.storage.get_num_full_hashes()
    echo('Database contains %d chunks, %d hash prefixes and %d full hashes' % (chunks, hash_prefixes, full_hashes))

def _setup_logger(log_level, log_file=None, silent=False):
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
    log.setLevel(log_level)
    if not silent:
        log.addHandler(ch)
    log.debug('Set up logging with level %s', log_level)
    log.log(TRACE, 'Logger has level %s', log.getEffectiveLevel())

def _get_log_level(log_level, debug=False, trace=False, dev=False):
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

def _run_sync(sbl, loop=True, exit_on_synced=False):
    """
    Synchronises the local database with the remote google servers.
    Takes a SafeBrowsingList Object as an argument.
    If loop is set to True it will update the database until it is in sync.
    """
    SLEEP_RETRY = 5
    i = 0
    while True:
        i += 1
        log.info("Syncing database, run #%d", i)
        try:
            def sync_sbl():
                return sbl.update_hash_prefix_cache()
            t = threading.Thread(target=sync_sbl)
            t.start()
            time.sleep(2)
            try:
                sleeping = int(sbl.prefix_list_protocol_client.sleeping_until - time.time() - 2)
                log.debug("sleeping for %d", sleeping)
                with click.progressbar(range(sleeping), fill_char='\u2588', empty_char='\u2591', show_eta=False) as bar:
                    for _second in bar:
                        time.sleep(1)
            except (ValueError, TypeError):
                pass
            t.join()
            if not loop:
                break
        except (KeyboardInterrupt, SystemExit):
            log.warning('Abort by user')
            sbl.prefix_list_protocol_client.stop_delay = True
            sys.exit(5)
        except urllib.error.URLError as e:
            log.error(e.reason)
            log.error('Are you connected to the internet? Failed to synchronize with GSB service: %s', e.reason)
            time.sleep(SLEEP_RETRY)
        except Exception as e:
            log.critical('Unknown error. Failed to synchronize with GSB service: %s', e)
            raise

if __name__ == '__main__':
    cli(None)
