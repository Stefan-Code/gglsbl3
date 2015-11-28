import click
from click.testing import CliRunner
import unittest
from nose.tools import *
from nose.tools import assert_in, assert_not_equals
import gglsbl3
from gglsbl3 import cli

class CliTest(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
    def tearDown(self):
        pass

    def test_help(self):
        result = self.runner.invoke(cli, ['--help'])
        print(result.output)
        #assert 'Usage: cli [OPTIONS] COMMAND [ARGS]' in result.output
        assert_in('Usage: cli [OPTIONS] COMMAND [ARGS]', result.output)
        #raise

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
