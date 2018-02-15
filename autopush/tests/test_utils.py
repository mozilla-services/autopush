import unittest

from mock import patch, Mock

from autopush.tests.test_integration import _get_vapid


class TestUserAgentParser(unittest.TestCase):
    def _makeFUT(self, *args):
        from autopush.utils import parse_user_agent
        return parse_user_agent(*args)

    def test_linux_extraction(self):
        dd, raw = self._makeFUT('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.2) Gecko/20090807 Mandriva Linux/1.9.1.2-1.1mud2009.1 (2009.1) Firefox/3.5.2 FirePHP/0.3,gzip(gfe),gzip(gfe)')  # NOQA
        assert dd["ua_os_family"] == "Linux"
        assert raw["ua_os_family"] == "Mandriva"

    def test_windows_extraction(self):
        dd, raw = self._makeFUT('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 (.NET CLR 3.5.30729)')  # NOQA
        assert dd["ua_os_family"] == "Windows"
        assert raw["ua_os_family"] == "Windows 7"

    def test_valid_os(self):
        dd, raw = self._makeFUT('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.5; rv:2.1.1) Gecko/ Firefox/5.0.1')  # NOQA
        assert dd["ua_os_family"] == "Mac OS X"
        assert raw["ua_os_family"] == "Mac OS X"

    def test_other_os_and_browser(self):
        dd, raw = self._makeFUT('BlackBerry9000/4.6.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102')  # NOQA
        assert dd["ua_os_family"] == "Other"
        assert raw["ua_os_family"] == "BlackBerry OS"
        assert dd["ua_browser_family"] == "Other"
        assert raw["ua_browser_family"] == "BlackBerry"

    def test_trusted_vapid(self):
        from autopush.utils import extract_jwt
        vapid_info = _get_vapid(payload={'sub': 'mailto:foo@example.com'})
        data = extract_jwt(vapid_info['auth'], 'invalid_key', is_trusted=True)
        assert data['sub'] == 'mailto:foo@example.com'

    @patch("requests.get")
    def test_get_amid_unknown(self, request_mock):
        import requests
        from autopush.utils import get_amid

        request_mock.side_effect = requests.HTTPError
        result = get_amid()
        assert result is None

    @patch("requests.get")
    def test_get_ec2_instance_id_unknown(self, request_mock):
        import requests
        from autopush.utils import get_ec2_instance_id

        request_mock.side_effect = requests.HTTPError
        result = get_ec2_instance_id()
        assert result is None

    @patch("requests.get")
    def test_get_ec2_instance_id(self, request_mock):
        from autopush.utils import get_ec2_instance_id
        mock_reply = Mock()
        mock_reply.content = "i-123242"

        request_mock.return_value = mock_reply
        result = get_ec2_instance_id()
        assert result == "i-123242"
