pylisp
======

This package provides an implementation of LISP, the Locator/ID
Separation Protocol in Python. This is an experimental protocol
where the IP addresses on the network define the identity of
the systems and a separate mapping system determines how the
data is routed to that network.

This library provides the means to parse and create LISP data
and control messages, as well as command line tools to perform
actions like asking a map resolver for a mapping and directly
querying a DDT node.

The intention is that in a later stage implementations for a
map server, map resolver and DDT node will also be provided.
