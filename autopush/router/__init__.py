"""Notification Routers

This package contains notification routers that handle routing a notification
through the appropriate system for a given client.

"""
from autopush.router.internal import InternalRouter


available_routers = {
    "internal_simplepush": InternalRouter,
}
