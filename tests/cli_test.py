import click
from click.testing import CliRunner
import unittest
import os
from nose.tools import *
from nose.tools import assert_in, assert_not_equals
import gglsbl3
from gglsbl3 import cli

class CliTest(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self.dbpath = './testdb-cli.sqlite'
    def tearDown(self):
        try:
            os.remove(self.dbpath)
        except FileNotFoundError:
            pass

    def test_help(self):
        result = self.runner.invoke(cli, ['--help'])
        print(result.output)
        assert_in('Usage: cli [OPTIONS] COMMAND [ARGS]', result.output)

    def test_version(self):
        result = self.runner.invoke(cli, ['--version'])
        assert_in(gglsbl3.__version__, result.output)

    def test_missing_api_key(self):
        result = self.runner.invoke(cli, ['--log-level', 'debug', 'lookup', 'google.com'])
        print(result)
        print(result.output)
        assert_not_equals(result.exit_code, 0)

    def test_fake_api_key_missing_command(self):
        result = self.runner.invoke(cli, ['--api-key', 'abcdefghijklmnop'])
        print(result)
        print(result.output)
        assert_in('Error: Missing command.', result.output)

    def test_fake_api_key_lookup(self):
        '''
        This test will never connect to the google servers and download
        full hashes because the database we are working on
        does not contain any prefixes.
        Thus no http mocking is needed.
        '''
        result = self.runner.invoke(cli, ['--api-key', 'abcdefghijklmnop', '--db-file', self.dbpath, 'lookup', 'google.com'])
        print(result)
        print(result.output)
        eq_(result.exit_code, 0)
