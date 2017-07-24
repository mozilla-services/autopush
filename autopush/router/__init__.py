"""Notification Routers

This package contains notification routers that handle routing a notification
through the appropriate system for a given client.

"""
from typing import Dict  # noqa

from twisted.web.client import Agent  # noqa

from autopush.db import DatabaseManager  # noqa
from autopush.router.apnsrouter import APNSRouter
from autopush.router.gcm import GCMRouter
from autopush.router.interface import IRouter  # noqa
from autopush.router.simple import SimpleRouter
from autopush.router.webpush import WebPushRouter
from autopush.router.fcm import FCMRouter
from autopush.settings import AutopushSettings  # noqa

__all__ = ["APNSRouter", "FCMRouter", "GCMRouter", "WebPushRouter",
           "SimpleRouter"]


def routers_from_settings(settings, db, agent):
    # type: (AutopushSettings, DatabaseManager, Agent) -> Dict[str, IRouter]
    """Create a dict of IRouters for the given settings"""
    router_conf = settings.router_conf
    routers = dict(
        webpush=WebPushRouter(settings, None, db, agent)
    )
    if settings.enable_simplepush:
        routers['simplepush'] = SimpleRouter(
            settings, router_conf.get("simplepush"), db, agent)
    if 'apns' in router_conf:
        routers["apns"] = APNSRouter(settings, router_conf["apns"], db.metrics)
    if 'gcm' in router_conf:
        routers["gcm"] = GCMRouter(settings, router_conf["gcm"], db.metrics)
    return routers
