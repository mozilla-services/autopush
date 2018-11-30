"""Notification Routers

This package contains notification routers that handle routing a notification
through the appropriate system for a given client.

"""
from typing import Dict  # noqa

from twisted.web.client import Agent  # noqa

from autopush.config import AutopushConfig  # noqa
from autopush.db import DatabaseManager  # noqa
from autopush.router.apnsrouter import APNSRouter
from autopush.router.gcm import GCMRouter
from autopush.router.interface import IRouter  # noqa
from autopush.router.webpush import WebPushRouter
from autopush.router.fcm import FCMRouter
from autopush.router.fcm_v1 import FCMv1Router
from autopush.router.adm import ADMRouter

__all__ = ["APNSRouter", "FCMRouter", "FCMv1Router", "GCMRouter",
           "WebPushRouter", "ADMRouter"]


def routers_from_config(conf, db, agent):
    # type: (AutopushConfig, DatabaseManager, Agent) -> Dict[str, IRouter]
    """Create a dict of IRouters for the given config"""
    router_conf = conf.router_conf
    routers = dict(
        webpush=WebPushRouter(conf, None, db, agent)
    )
    if 'apns' in router_conf:
        routers["apns"] = APNSRouter(conf, router_conf["apns"], db.metrics)
    if 'gcm' in router_conf:
        routers["gcm"] = GCMRouter(conf, router_conf["gcm"], db.metrics)
    if 'adm' in router_conf:
        routers["adm"] = ADMRouter(conf, router_conf["adm"], db.metrics)
    if 'fcm' in router_conf:
        # There are two forms of FCM that can be used. "Legacy" and "v1".
        # While possible, they really should not be used in parallel, and only
        # one form should be defined.
        if router_conf['fcm']['version'] == 0:
            routers["fcm"] = FCMRouter(conf, router_conf["fcm"], db.metrics)
        if router_conf['fcm']['version'] == 1:
            routers["fcm"] = FCMv1Router(conf, router_conf["fcm"], db.metrics)
    return routers
