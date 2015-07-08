"""Notification Routers

This package contains notification routers that handle routing a notification
through the appropriate system for a given client.

"""
from autopush.router.apnsrouter import APNSRouter
from autopush.router.gcm import GCMRouter
from autopush.router.simple import SimpleRouter
from autopush.router.webpush import WebPushRouter

__all__ = ["APNSRouter", "GCMRouter", "SimpleRouter", "WebPushRouter"]
