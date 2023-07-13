.. _glossary:

 🚨 🚨 🚨 🚨 🚨 🚨 🚨

╔═════════════════════════════════════════════════════════════╗
 **Note**: *This document is obsolete.*
 Please refer to `Autopush Documentation <https://mozilla-services.github.io/autopush-rs>`_ on GitHub.
╚═════════════════════════════════════════════════════════════╝

 🚨 🚨 🚨 🚨 🚨 🚨 🚨


Glossary
========


.. glossary::

    AppServer
        A third-party Application Server that delivers notifications to client
        applications via Push.

    Bridging
       Using a third party or proprietary network in order to deliver
       Push notifications to an App. This may be preferred for mobile devices
       where such a network may improve battery life or other reasons.

    Channel
       A unique route between an :term:`AppServer` and the Application. May
       also be referred to as :term:`Subscription`

    CHID
       The Channel Subscription ID. Push assigns each subscription (or channel)
       a unique identifier.

    Message-ID
       A unique message ID. Each message for a given subscription is given a
       unique identifier that is returned to the :term:`AppServer` in the
       ``Location`` header.

    Notification
       A message sent to an endpoint node intended for delivery to a HTTP
       endpoint. Autopush stores these in the message tables.

    Router Type
       Every :term:`UAID` that connects has a router type. This indicates the
       type of routing to use when dispatching notifications. For most clients, this
       value will be ``webpush``. Clients using :term:`Bridging` it will use either
       ``gcm``, ``fcm``, ``apns``, or ``adm``.

    Subscription
       A unique route between an :term:`AppServer` and the Application. May
       also be referred to as a :term:`Channel`

    UAID
       The Push User Agent Registration ID. Push assigns each remote recipient
       (Firefox client) a unique identifier. These may occasionally be reset
       by the Push Service or the client.

    WebPush
       An IETF standard for communication between Push Services, the clients,
       and application servers.

       See: https://datatracker.ietf.org/doc/draft-ietf-webpush-protocol/
