import unittest

from mock import Mock, patch
from nose.tools import eq_, ok_


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
        eq_(cli.db.router.table.table_name, "fred")

    def test_bad_endpoint(self):
        cli = self._makeFUT([
            "--router_tablename=fred",
            "http://someendpoint",
        ])
        returncode = cli.run()
        ok_(returncode not in (None, 0))

    @patch("autopush.diagnostic_cli.AutopushConfig")
    @patch("autopush.diagnostic_cli.DatabaseManager.from_config")
    def test_successfull_lookup(self, mock_db_cstr, mock_settings_class):
        from autopush.diagnostic_cli import run_endpoint_diagnostic_cli
        mock_settings_class.return_value = mock_settings = Mock()
        mock_settings.parse_endpoint.return_value = dict(
            uaid="asdf", chid="asdf")

        mock_db_cstr.return_value = mock_db = Mock()
        mock_db.router.get_uaid.return_value = mock_item = FakeDict()
        mock_item._data = {}
        mock_item["current_month"] = "201608120002"
        mock_message_table = Mock()
        mock_db.message_tables = {"201608120002": mock_message_table}

        run_endpoint_diagnostic_cli([
            "--router_tablename=fred",
            "http://something/wpush/v1/legit_endpoint",
        ], use_files=False)
        mock_message_table.all_channels.assert_called()
