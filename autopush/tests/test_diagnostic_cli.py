import unittest

from mock import Mock, patch
from moto import mock_dynamodb2
from nose.tools import eq_, ok_


mock_dynamodb2 = mock_dynamodb2()


def setUp():
    mock_dynamodb2.start()


def tearDown():
    mock_dynamodb2.stop()


class FakeDict(dict):
    pass


class DiagnosticCLITestCase(unittest.TestCase):
    def _makeFUT(self, *args, **kwargs):
        from autopush.diagnostic_cli import EndpointDiagnosticCLI
        return EndpointDiagnosticCLI(*args, use_files=False, **kwargs)

    def test_basic_load(self):
        cli = self._makeFUT([
            "--router_tablename=fred",
            "http://someendpoint",
        ])
        eq_(cli._settings.router_table.table_name, "fred")

    def test_bad_endpoint(self):
        cli = self._makeFUT([
            "--router_tablename=fred",
            "http://someendpoint",
        ])
        assert cli.run()

    @patch("autopush.diagnostic_cli.AutopushSettings")
    def test_successfull_lookup(self, mock_settings_class):
        from autopush.diagnostic_cli import run_endpoint_diagnostic_cli
        mock_settings_class.return_value = mock_settings = Mock()
        mock_settings.parse_endpoint.return_value = dict(
            uaid="asdf", chid="asdf")
        mock_settings.router.get_uaid.return_value = mock_item = FakeDict()
        mock_item._data = {}
        mock_item["current_month"] = "201608120002"
        mock_message_table = Mock()
        mock_settings.message_tables = {"201608120002": mock_message_table}

        run_endpoint_diagnostic_cli([
            "--router_tablename=fred",
            "http://something/wpush/v1/legit_endpoint",
        ], use_files=False)
        mock_message_table.all_channels.assert_called()
