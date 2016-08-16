from cyclone import httpserver
from twisted.logger import Logger


class LimitedHTTPConnection(httpserver.HTTPConnection):
    """
    Limit the amount of data being sent to a reasonable amount.

    twisted already limits TCP streamed chunk reads to 65K, with
    ~16k per header line. By default, we'll limit the number of
    header lines to 100, and the maximum amount of data for the body
    to be 4K.

    """
    maxHeaders = 100
    maxData = 1024*4

    def lineReceived(self, line):
        """Process a header line of data, ensuring we have not exceeded the
        max number of allowable headers.

        :param line: raw header line
        """
        if line:
            if len(self._headersbuffer) == self.maxHeaders:
                Logger().warn("Too many headers sent, terminating connection")
                return self.lineLengthExceeded(line)
            self._headersbuffer.append(line + self.delimiter)
        else:
            buff = "".join(self._headersbuffer)
            self._headersbuffer = []
            self._on_headers(buff)

    def rawDataReceived(self, data):
        """Process a raw chunk of data, ensuring we have not exceeded the
        max size of a data block

        :param data: raw data block
        """
        if len(data) > self.maxData:
            Logger().warn("Too much data sent, terminating connection")
            return self.lineLengthExceeded(data)
        if self.content_length is not None:
            data, rest = data[:self.content_length], data[self.content_length:]
            self.content_length -= len(data)
        else:
            rest = ''

        self._contentbuffer.write(data)
        if self.content_length <= 0:
            self._contentbuffer.seek(0, 0)
            self._on_request_body(self._contentbuffer.read())
            self._content_length = self._contentbuffer = None
            self.setLineMode(rest)
