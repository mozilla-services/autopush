from __future__ import print_function

import pprint
import re
import sys

import configargparse
from twisted.logger import Logger

from autopush.main import (
    add_shared_args,
    shared_config_files,
)
from autopush.settings import AutopushSettings


PUSH_RE = re.compile(r"push/(?:(?P<api_ver>v\d+)\/)?(?P<token>[^\/]+)")


class EndpointDiagnosticCLI(object):
    log = Logger()

    def __init__(self, sysargs, use_files=True):
        args = self._load_args(sysargs, use_files)
        self._settings = AutopushSettings(
            crypto_key=args.crypto_key,
            router_tablename=args.router_tablename,
            storage_tablename=args.storage_tablename,
            message_tablename=args.message_tablename,
        )
        self._endpoint = args.endpoint
        self._pp = pprint.PrettyPrinter(indent=4)

    def _load_args(self, sysargs, use_files):
        if use_files:
            config_files = shared_config_files + [  # pragma: nocover
                '/etc/autopush_endpoint.ini',
                '~/.autopush_endpoint.ini',
                '.autopush_endpoint.ini'
            ]
        else:
            config_files = []  # pragma: nocover

        parser = configargparse.ArgumentParser(
            description='Runs endpoint diagnostics.',
            default_config_files=config_files)
        parser.add_argument('endpoint', help="Endpoint to parse")

        add_shared_args(parser)
        return parser.parse_args(sysargs)

    def run(self):
        match = PUSH_RE.search(self._endpoint)
        if not match:
            sys.exit("Not a valid endpoint")
            return  # Included purely for testing purposes

        md = match.groupdict()
        api_ver, token = md.get("api_ver", "v0"), md["token"]

        parsed = self._settings.parse_endpoint(
            token=token,
            version=api_ver,
        )
        uaid, chid = parsed["uaid"], parsed["chid"]

        print("UAID: {}\nCHID: {}\n".format(uaid, chid))

        rec = self._settings.router.get_uaid(uaid)
        print("Router record:")
        self._pp.pprint(rec._data)
        print("\n")

        mess_table = rec["current_month"]
        chans = self._settings.message_tables[mess_table].all_channels(uaid)
        print("Channels in message table:")
        self._pp.pprint(chans)


def run_endpoint_diagnostic_cli(sysargs=None, use_files=True):
    cli = EndpointDiagnosticCLI(sysargs, use_files)
    cli.run()
