import unittest

from mock import Mock, patch

import autopush.tests


class FakeDict(dict):
    pass


class DiagnosticCLITestCase(unittest.TestCase):
    def _makeFUT(self, *args, **kwargs):
        from autopush.diagnostic_cli import EndpointDiagnosticCLI
        return EndpointDiagnosticCLI(
            *args,
            resource=autopush.tests.boto_resource,
            use_files=False,
            **kwargs)

    def test_basic_load(self):
        cli = self._makeFUT([
            "--router_tablename=fred",
            "http://someendpoint",
        ])
        assert cli.db.router.table().table_name == "fred"

    def test_bad_endpoint(self):
        cli = self._makeFUT([
            "--router_tablename=fred",
            "http://someendpoint",
        ])
        returncode = cli.run()
        assert returncode not in (None, 0)

    @patch("autopush.diagnostic_cli.Message")
    @patch("autopush.diagnostic_cli.AutopushConfig")
    @patch("autopush.diagnostic_cli.DatabaseManager.from_config")
    def test_successfull_lookup(self, mock_db_cstr, mock_conf_class, mock_msg):
        from autopush.diagnostic_cli import run_endpoint_diagnostic_cli
        mock_conf_class.return_value = mock_conf = Mock()
        mock_conf.parse_endpoint.return_value = dict(
            uaid="asdf", chid="asdf")

        mock_db_cstr.return_value = mock_db = Mock()
        mock_db.router.get_uaid.return_value = mock_item = FakeDict()
        mock_item._data = {}
        mock_item["current_month"] = "201608120002"
        mock_db.message_tables = ["2016081200002"]
        mock_msg.return_value = mock_message = Mock()

        run_endpoint_diagnostic_cli(
            sysargs=[
                "--router_tablename=fred",
                "http://something/wpush/v1/legit_endpoint",
            ],
            use_files=False,
            resource=autopush.tests.boto_resource)
        mock_message.all_channels.assert_called()

    def test_parser_tuple(self):
        from autopush.diagnostic_cli import EndpointDiagnosticCLI

        edc = EndpointDiagnosticCLI(
            ("http://someendpoint",),
            use_files=False,
            resource=autopush.tests.boto_resource
        )
        assert edc is not None
        assert edc._endpoint == "http://someendpoint"
