import json
import time

from boto.dynamodb2.exceptions import ProvisionedThroughputExceededException
from cryptography.fernet import InvalidToken
from pyramid.response import Response

NOT_DELIVERED = 0
INVALID_UAID = 1
DELIVERED = 2


def endpoint(request):
    app_settings = request.registry.app_settings
    requests = app_settings.requests
    fernet = app_settings.fernet
    token = request.matchdict["token"]
    request.content_type = "application/x-www-form-urlencoded"

    # Find where version/data is hanging out
    version = request.GET.get("version") or request.POST.get("version")
    data = request.GET.get("data") or request.POST.get("data")
    if version is None:
        return Response("No version", status=401)

    if isinstance(version, list):
        version = version[0]

    try:
        token_data = fernet.decrypt(token.encode('utf8'))
    except InvalidToken:
        return Response("Invalid Token", status=401)

    uaid, chid = token_data.split(":")
    if not version:
        version = int(time.time())

    storage, router = app_settings.storage, app_settings.router

    try:
        result = attempt_delivery(requests, router, uaid, chid, version, data)
    except ProvisionedThroughputExceededException:
        return Response("Server too busy.", status=503)

    if result == DELIVERED:
        return Response("Success")
    elif result == INVALID_UAID:
        return Response("Invalid UAID", status=401)

    # Uaid not found, or not delivered
    # TODO: Maybe do another check and see if they've connected since the
    #       last one
    try:
        storage.save_notification(uaid=uaid, chid=chid, version=version)
    except ProvisionedThroughputExceededException:
        return Response("Server too busy.", status=503)

    return Response("Success")


def attempt_delivery(requests, router, uaid, chid, version, data):
    # Lookup the uaid
    item = router.get_uaid(uaid)
    if not item:
        return Response("Invalid", status=404)

    # If uaid has never connected, its invalid
    node_id = item.get("node_id")
    if not node_id:
        return INVALID_UAID

    payload = json.dumps([{"channelID": chid,
                           "version": int(version),
                           "data": data}])
    result = requests.put(node_id + "/" + uaid, data=payload)
    if result.status_code == 200:
        return DELIVERED
    elif result.status_code == 404:
        # Nuke this entry from router, as they're not there anymore
        # TODO: Be interested if this fails, cause they might be on a node
        #       now
        router.clear_node(item)
    return NOT_DELIVERED
