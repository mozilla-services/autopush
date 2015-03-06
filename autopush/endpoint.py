from cryptography.fernet import InvalidToken
from pyramid.config import Configurator
from pyramid.response import Response


def endpoint(request):
    fernet = request.registry.fernet
    try:
        data = fernet.decrypt(token.encode('utf8'))
    except InvalidToken:
        self.set_status(401)
        return self.write("Invalid")

    uaid, chid = data.decode('utf8').split(":")
    if uaid not in globs.clients:
        self.set_status(401)
        return self.write("Invalid")

    version = self.get_argument('version', default=None)
    data = self.get_argument('data', default=None)

    if version is None or version == []:
        vs = urlparse.parse_qs(self.request.body,
                               keep_blank_values=True)
        version = vs.get("version")
        data = vs.get("data")

    if version is None or uaid not in globs.clients:
        # Still None? Ditch it.
        self.set_status(401)
        return self.write("Invalid")

    if isinstance(version, list):
        version = version[0]

    if data and len(data) > globs.MAX_DATA_PAYLOAD:
        self.set_status(401)
        return self.write("Data too large")

    if version == "":
        version = str(int(time.time()))

    globs.clients[uaid].send_notifications([(chid, version, data)])
    return ""
