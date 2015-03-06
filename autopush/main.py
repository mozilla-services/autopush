"""autopush daemon script"""
import sys
import argparse

from autobahn.twisted.websocket import WebSocketServerFactory
from twisted.python import log
from twisted.internet import reactor

from autopush.server import SimplePushServerProtocol, site
from autopush.settings import AutopushSettings

def _parse(sysargs=None):
    if sysargs is None:
        sysargs = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Runs a Loads broker.')
    parser.add_argument('-p', '--port', help='HTTP Port', type=int,
                        default=8080)
    parser.add_argument('--debug', help='Debug Info.', action='store_true',
                        default=True)
    parser.add_argument('--influx-password', help='InfluxDB password',
                        type=str, default='root')
    parser.add_argument('--influx-secure', help='Use TLS for InfluxDB',
                        action='store_true', default=False)
    parser.add_argument('--initial-db', help="JSON file to initialize the db.",
                        type=str, default='pushgo.json')

    args = parser.parse_args(sysargs)
    return args, parser


def main(sysargs=None):
    settings = AutopushSettings()

    log.startLogging(sys.stdout)

    factory = WebSocketServerFactory("ws://localhost:8080/", debug=False)
    factory.protocol = SimplePushServerProtocol
    factory.protocol.settings = settings

    reactor.listenTCP(8080, factory)
    reactor.listenTCP(8081, site)
    try:
        reactor.run()
    except KeyboardInterrupt:
        log.debug('Bye')

if __name__ == '__main__':
    main()
