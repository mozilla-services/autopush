import json
import time

from cryptography.fernet import InvalidToken
from pyramid.response import Response


def provision_exceeded(request):
    return Response("Server too busy.", status=503)


def endpoint(request):
    start_time = time.time()
    app_settings = request.registry.app_settings
    metrics = app_settings.metrics
    requests = app_settings.requests
    fernet = app_settings.fernet
    token = request.matchdict["token"]
    request.content_type = "application/x-www-form-urlencoded"

    # Find where version/data is hanging out
    version = request.GET.get("version") or request.POST.get("version")
    data = request.GET.get("data") or request.POST.get("data")
    if version is None:
        return Response("No version", status=401)

    if data and len(data) > app_settings.max_data:
        metrics.increment("updates.appserver.toolong")
        return Response("Data too large", status=401)

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

    # First determine whether they've ever connected, should be
    # a record
    item = router.get_uaid(uaid)
    if not item:
        return Response("Invalid", status=404)

    # Determine if they're connected at the moment
    node_id = item.get("node_id")

    # Attempt a delivery if they are connected
    client_check = False
    if node_id:
        payload = json.dumps([{"channelID": chid,
                               "version": int(version),
                               "data": data}])
        result = requests.put(node_id + "/push/" + uaid, data=payload)

        if result.status_code == 200:
            # Success, return!
            metrics.increment("router.broadcast.hit")
            time_diff = time.time() - start_time
            metrics.timing("updates.handled", duration=time_diff)
            return Response("Success")
        elif result.status_code == 404:
            # Conditionally delete the node_id
            cleared = router.clear_node(item)

            if not cleared:
                # Client hopped, punt this request so app-server can
                # try again and get luckier
                return Response("Server is Busy", status=503)
        elif result.status_code == 503:
            # Client was busy, remember to tell it to check
            client_check = True

    # At this point its time to save the notification
    storage.save_notification(uaid=uaid, chid=chid, version=version)

    # If we need to tell a client to check...
    if client_check:
        result = requests.put(node_id + "/notif/" + uaid)
        if result == 404:
            # Client jumped, if they reconnected somewhere, try one
            # more time
            item = router.get_uaid(uaid)
            if not item:
                # Client got deleted too? bummer.
                return Response("Invalid", status=404)
            node_id = item.get("node_id")
            requests.put(node_id + "/notif/" + uaid)
            # No check on response here, because if they jumped since we
            # got this they'll definitely get the stored notification

    metrics.increment("router.broadcast.miss")
    return Response("Success")
