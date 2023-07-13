.. _rust:

 🚨 🚨 🚨 🚨 🚨 🚨 🚨

╔═════════════════════════════════════════════════════════════╗
 **Note**: *This document is obsolete.*
 Please refer to `Autopush Documentation <https://mozilla-services.github.io/autopush-rs>`_ on GitHub.
╚═════════════════════════════════════════════════════════════╝

 🚨 🚨 🚨 🚨 🚨 🚨 🚨

=================
Migrating to Rust
=================

Progress never comes from resting. One of the significant considerations of running a service that needs to communicate
with hundreds of millions of clients is cost. We are forced to continually evaluate and optimize. When a lower cost
option is presented, we seriously consider it.

There is some risk, of course, so rapid change is avoided and testing is strongly encouraged. As of early 2018, the
decision was made to move the costlier elements of the server to Rust. The rust based application is at
`autopush-rs`_.

Why Rust?
=========

Rust is a strongly typed, memory efficient language. It has matured rapidly and offers structure that vastly reduces
the memory requirements for running connections. As a bonus, it’s also forced us to handle potential bugs, making the
service more reliable.

The current python environment we use (pypy) continues to improve as well, but does not offer the sort of improvements
that rust does when it comes to handling socket connections.

To that end we’re continuing to use pypy for the endpoint connection management for the time being.

When is the switch going to happen?
===================================

As of the end of June 2018, our rust handler is in testing. We expect to deploy it soon, but since this deployment
should not impact external users, we’re not rushing to deploy just to hit an arbitrary milestone. It will be deployed
when all parties have determined it’s ready.

What will happen to autopush?
=============================

Currently, the plan is to maintain it so long as it’s in production use. Since we plan on continuing to have autopush
handle endpoints for some period, even after autopush-rs has been deployed to production and is handling connections.
However, we do reserve the right to archive this repo at some future date.


.. _`autopush-rs`: https://github.com/mozilla-services/autopush-rs
