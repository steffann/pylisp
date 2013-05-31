'''
Created on 11 mrt. 2013

@author: sander
'''
from .base import AbstractNode
from ipaddress import IPv6Address, IPv4Address


class DDTReferralNode(AbstractNode):
    def __init__(self, prefix, ddt_servers=None):
        super(DDTReferralNode, self).__init__(prefix)
        self._ddt_servers = set()

        if ddt_servers:
            self.update(ddt_servers)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self._prefix,
                               self._ddt_servers)

    def __iter__(self):
        return iter(self._ddt_servers)

    def __len__(self):
        return len(self._ddt_servers)

    def add(self, ddt_server):
        assert isinstance(ddt_server, (IPv4Address, IPv6Address))

        # Add the new server
        self._ddt_servers.add(ddt_server)

    def clear(self):
        self._ddt_servers = set()

    def __contains__(self, ddt_server):
        return ddt_server in self._ddt_servers

    def copy(self):
        return self.__class__(self._prefix, self._ddt_servers)

    def discard(self, ddt_server):
        self._ddt_servers.discard(ddt_server)

    def remove(self, ddt_server):
        self._ddt_servers.remove(ddt_server)

    def update(self, ddt_servers):
        for ddt_server in ddt_servers:
            self.add(ddt_server)
