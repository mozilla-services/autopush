# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from urllib import urlencode
import requests
import time

""" Client disconnect and remote wake. """

class WakeException(Exception):
    pass

class IWake(object):
    """ Wake interface

    Several protocol extensions provide for an external "wake" option.
    For instance, a vendor provided UDP wake extension for simplePush allows
    servers to use a proprietary system that sends a UDP based wake message
    to devices. This message bears no data or version information and only
    wakes a device that may not be actively connected to the network.

    """

    def __init__(self, *args, **kwargs):
        """ Setup """

    def register(self, wake_info=None):
        """ Endpoint Registration """

    def set_active(self):
        """Set period to time out and the destruction method"""

    def check_idle(self):
        """ Check if the connection has idled out """

    def send_wake(self, wake_info=None):
        """ Send a wake notification to the device """


class UDPWake(IWake):
    """ Proprietary UDP wake tool """

    data = {}
    default_period = 10 * 1000  # default to 10 seconds
    endpoint = None     # Third party wake endpoint
    timeout = 0
    idle = 0

    def _ms_time(self):
        return int(time.time() * 1000)

    def __init__(self, protocol=None, timeout=0, kill_func=None,
                 host=None, cert=None, **kwargs):
        self.idler = None
        self.protocol = protocol
        self.endpoint = host
        self.cert = cert
        if timeout > 0 and (protocol is None or kill_func is None):
            raise ValueError("No protocol or kill function specified")
        self.timeout = timeout
        self.kill_func = kill_func
        self.kill_args = kwargs

    def register(self, info):
        """Set the Wake info, usually done in 'hello'. This isn't really
           useful for UDP, since the socket and the endpoint don't share
           waker objects.
        """
        pass

    def set_active(self):
        """reset the idle timer"""
        self.idle = self._ms_time()

    def check_idle(self):
        """Check to see if we need to kill the link"""
        if self.idler is not None:
            self.idler.cancel()
        try:
            if self.timeout > 0 and self.idle > 0:
                if self._ms_time() - self.idle >= self.timeout * 1000:
                    self.kill_func(**self.kill_args)
                    return
                self.idler = self.protocol.deferToLater(self.timeout,
                                                        self.check_idle);
        except (KeyError, AttributeError):
            # More than likely, this isn't a UDP wake connection.
            pass

    def send_wake(self, wake_info=None):
        """Send a wake request to the external endpoint."""
        if wake_info is None:
            wake_info = self.info
        response = requests.post(
                self.endpoint,
                data=urlencode(wake_info["data"]),
                cert=self.cert)
        if response.status_code < 200 or response.status_code >= 300:
            raise WakeException()
