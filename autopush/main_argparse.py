"""autopush/autoendpoint/etc script command line parsing"""
import configargparse


def add_shared_args(parser):
    """Add's a large common set of shared arguments"""
    parser.add_argument('--config-shared',
                        help="Common configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('--debug', help='Debug Info.', action="store_true",
                        default=False, env_var="DEBUG")
    parser.add_argument('--log_level', help='Log level to log', type=str,
                        default="", env_var="LOG_LEVEL")
    parser.add_argument('--log_output', help="Log output, stdout or filename",
                        default="stdout", env_var="LOG_OUTPUT")
    parser.add_argument('--firehose_stream_name', help="Firehose Delivery"
                        " Stream Name", default="", env_var="STREAM_NAME",
                        type=str)
    parser.add_argument('--crypto_key', help="Crypto key for tokens",
                        default=None, env_var="CRYPTO_KEY", type=str,
                        action="append")
    parser.add_argument('--key_hash', help="Key to hash IDs for storage",
                        default="", env_var="KEY_HASH", type=str)
    parser.add_argument('--datadog_api_key', help="DataDog API Key", type=str,
                        default="", env_var="DATADOG_API_KEY")
    parser.add_argument('--datadog_app_key', help="DataDog App Key", type=str,
                        default="", env_var="DATADOG_APP_KEY")
    parser.add_argument('--datadog_flush_interval',
                        help="DataDog Flush Interval", type=int,
                        default=10, env_var="DATADOG_FLUSH_INTERVAL")
    parser.add_argument('--hostname', help="Hostname to announce under",
                        type=str, default=None, env_var="LOCAL_HOSTNAME")
    parser.add_argument('--resolve_hostname',
                        help="Resolve the announced hostname",
                        action="store_true", default=False,
                        env_var="RESOLVE_HOSTNAME")
    parser.add_argument('--statsd_host', help="Statsd Host", type=str,
                        default="localhost", env_var="STATSD_HOST")
    parser.add_argument('--statsd_port', help="Statsd Port", type=int,
                        default=8125, env_var="STATSD_PORT")
    parser.add_argument('--ssl_key', help="SSL Key path", type=str,
                        default="", env_var="SSL_KEY")
    parser.add_argument('--ssl_cert', help="SSL Cert path", type=str,
                        default="", env_var="SSL_CERT")
    parser.add_argument('--ssl_dh_param',
                        help="SSL DH Param file (openssl dhparam 1024)",
                        type=str, default=None, env_var="SSL_DH_PARAM")
    parser.add_argument('--router_tablename', help="DynamoDB Router Tablename",
                        type=str, default="router", env_var="ROUTER_TABLENAME")
    parser.add_argument('--message_tablename',
                        help="DynamoDB Message Tablename", type=str,
                        default="message", env_var="MESSAGE_TABLENAME")
    parser.add_argument('--message_read_throughput',
                        help="DynamoDB message read throughput",
                        type=int, default=5, env_var="MESSAGE_READ_THROUGHPUT")
    parser.add_argument('--message_write_throughput',
                        help="DynamoDB message write throughput",
                        type=int, default=5,
                        env_var="MESSAGE_WRITE_THROUGHPUT")
    parser.add_argument('--router_read_throughput',
                        help="DynamoDB router read throughput",
                        type=int, default=5, env_var="ROUTER_READ_THROUGHPUT")
    parser.add_argument('--router_write_throughput',
                        help="DynamoDB router write throughput",
                        type=int, default=5, env_var="ROUTER_WRITE_THROUGHPUT")
    parser.add_argument('--connection_timeout',
                        help="Seconds to wait for connection timeout",
                        type=int, default=1, env_var="CONNECTION_TIMEOUT")
    parser.add_argument('--max_data', help="Max data segment length in bytes",
                        default=4096, env_var='MAX_DATA')
    parser.add_argument('--env',
                        help="The environment autopush is running under",
                        default='development', env_var='AUTOPUSH_ENV')
    parser.add_argument('--endpoint_scheme', help="HTTP Endpoint Scheme",
                        type=str, default="http", env_var="ENDPOINT_SCHEME")
    parser.add_argument('--endpoint_hostname', help="HTTP Endpoint Hostname",
                        type=str, default=None, env_var="ENDPOINT_HOSTNAME")
    parser.add_argument('-e', '--endpoint_port', help="HTTP Endpoint Port",
                        type=int, default=8082, env_var="ENDPOINT_PORT")
    parser.add_argument('--human_logs', help="Enable human readable logs",
                        action="store_true", default=False,
                        env_var="HUMAN_LOGS")
    parser.add_argument('--no_aws', help="Skip AWS meta information checks",
                        action="store_true", default=False)
    parser.add_argument('--msg_limit', help="Max limit for messages per uaid "
                        "before reset", type=int, default="100",
                        env_var="MSG_LIMIT")
    parser.add_argument('--memusage_port',
                        help="Enable the debug _memusage API on Port",
                        type=int, default=None,
                        env_var='MEMUSAGE_PORT')
    parser.add_argument('--use_cryptography',
                        help="Use the cryptography library vs. JOSE",
                        action="store_true",
                        default=False, env_var="USE_CRYPTOGRAPHY")
    # No ENV because this is for humans
    _add_external_router_args(parser)
    _obsolete_args(parser)


def _obsolete_args(parser):
    """ Obsolete and soon to be disabled configuration arguments.

    These are included to prevent startup errors with old config files.

    """
    parser.add_argument('--external_router', help='OBSOLETE')
    parser.add_argument('--max_message_size', type=int, help="OBSOLETE")
    parser.add_argument('--s3_bucket', help='OBSOLETE')
    parser.add_argument('--senderid_expry', help='OBSOLETE')
    parser.add_argument('--proxy_protocol', help="OBSOLETE")
    # old APNs args
    parser.add_argument('--apns_enabled', help="OBSOLETE")
    parser.add_argument('--apns_sandbox', help="OBSOLETE")
    parser.add_argument('--apns_cert_file', help="OBSOLETE")
    parser.add_argument('--apns_key_file', help="OBSOLETE")

    # UDP
    parser.add_argument('--wake_timeout', help="OBSOLETE")
    parser.add_argument('--wake_pem', help="OBSOLETE")
    parser.add_argument('--wake_server', help="OBSOLETE")

    parser.add_argument('--disable_simplepush', help="OBSOLETE")
    parser.add_argument('--storage_tablename', help="OBSOLETE")
    parser.add_argument('--storage_read_throughput', help="OBSOLETE")
    parser.add_argument('--storage_write_throughput', help="OBSOLETE")


def _add_external_router_args(parser):
    """Parses out external router arguments"""
    # GCM
    parser.add_argument('--gcm_enabled', help="Enable GCM Bridge",
                        action="store_true", default=False,
                        env_var="GCM_ENABLED")
    label = "GCM Router:"
    parser.add_argument('--gcm_ttl', help="%s Time to Live" % label,
                        type=int, default=60, env_var="GCM_TTL")
    parser.add_argument('--gcm_dryrun',
                        help="%s Dry run (no message sent)" % label,
                        action="store_true", default=False,
                        env_var="GCM_DRYRUN")
    parser.add_argument('--gcm_collapsekey',
                        help="%s string to collapse messages" % label,
                        type=str, default="simplepush",
                        env_var="GCM_COLLAPSEKEY")
    parser.add_argument('--senderid_list', help='GCM SenderIDs/auth keys',
                        type=str, default="{}")
    # FCM
    parser.add_argument('--fcm_enabled', help="Enable FCM Bridge",
                        action="store_true", default=False,
                        env_var="FCM_ENABLED")
    label = "FCM Router:"
    parser.add_argument('--fcm_ttl', help="%s Time to Live" % label,
                        type=int, default=60, env_var="FCM_TTL")
    parser.add_argument('--fcm_dryrun',
                        help="%s Dry run (no message sent)" % label,
                        action="store_true", default=False,
                        env_var="FCM_DRYRUN")
    parser.add_argument('--fcm_collapsekey',
                        help="%s string to collapse messages" % label,
                        type=str, default="simplepush",
                        env_var="FCM_COLLAPSEKEY")
    parser.add_argument('--fcm_auth', help='Auth Key for FCM',
                        type=str, default="")
    parser.add_argument('--fcm_senderid', help='SenderID for FCM',
                        type=str, default="")
    # Apple Push Notification system (APNs) for iOS
    # credentials consist of JSON struct containing a channel type
    # followed by the settings,
    # e.g. {'firefox':{'cert': 'path.cert', 'key': 'path.key',
    #                  'sandbox': false}, ... }
    parser.add_argument('--apns_creds', help="JSON dictionary of "
                                             "APNS settings",
                        type=str, default="",
                        env_var="APNS_CREDS")


def parse_connection(config_files, args):
    """Parse out connection node arguments for an autopush node"""
    parser = configargparse.ArgumentParser(
        description='Runs a Connection Node.',
        default_config_files=config_files,
        )
    parser.add_argument('--config-connection',
                        help="Connection node configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('-p', '--port', help='Websocket Port', type=int,
                        default=8080, env_var="PORT")
    parser.add_argument('--router_hostname',
                        help="HTTP Router Hostname to use for internal "
                        "router connects", type=str, default=None,
                        env_var="ROUTER_HOSTNAME")
    parser.add_argument('-r', '--router_port',
                        help="HTTP Router Port for internal router connects",
                        type=int, default=8081, env_var="ROUTER_PORT")
    parser.add_argument('--router_ssl_key',
                        help="Routing listener SSL key path", type=str,
                        default="", env_var="ROUTER_SSL_KEY")
    parser.add_argument('--router_ssl_cert',
                        help="Routing listener SSL cert path", type=str,
                        default="", env_var="ROUTER_SSL_CERT")
    parser.add_argument('--auto_ping_interval',
                        help="Interval between Websocket pings", default=0,
                        type=float, env_var="AUTO_PING_INTERVAL")
    parser.add_argument('--auto_ping_timeout',
                        help="Timeout in seconds for Websocket ping replys",
                        default=4, type=float, env_var="AUTO_PING_TIMEOUT")
    parser.add_argument('--max_connections',
                        help="The maximum number of concurrent connections.",
                        default=0, type=int, env_var="MAX_CONNECTIONS")
    parser.add_argument('--close_handshake_timeout',
                        help="The WebSocket closing handshake timeout. Set to "
                        "0 to disable.", default=0, type=int,
                        env_var="CLOSE_HANDSHAKE_TIMEOUT")
    parser.add_argument('--hello_timeout',
                        help="The client handshake timeout. Set to 0 to"
                        "disable.", default=0, type=int,
                        env_var="HELLO_TIMEOUT")

    add_shared_args(parser)
    return parser.parse_args(args)


def parse_endpoint(config_files, args):
    """Parses out endpoint arguments for an autoendpoint node"""
    parser = configargparse.ArgumentParser(
        description='Runs an Endpoint Node.',
        default_config_files=config_files,
        )
    parser.add_argument('--config-endpoint',
                        help="Endpoint node configuration file path",
                        dest='config_file', is_config_file=True)
    parser.add_argument('-p', '--port', help='Public HTTP Endpoint Port',
                        type=int, default=8082, env_var="PORT")
    parser.add_argument('--no_cors', help='Disallow CORS PUTs for update.',
                        action="store_true",
                        default=False, env_var='ALLOW_CORS')
    parser.add_argument('--auth_key', help='Bearer Token source key',
                        type=str, default=[], env_var='AUTH_KEY',
                        action="append")
    parser.add_argument('--client_certs',
                        help="Allowed TLS client certificates",
                        type=str, env_var='CLIENT_CERTS', default="{}")
    parser.add_argument('--proxy_protocol_port',
                        help="Enable a secondary Endpoint Port with HAProxy "
                        "Proxy Protocol handling",
                        type=int, default=None,
                        env_var='PROXY_PROTOCOL_PORT')

    add_shared_args(parser)
    return parser.parse_args(args)
