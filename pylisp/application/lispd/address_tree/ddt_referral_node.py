'''
Created on 11 mrt. 2013

@author: sander
'''
from ipaddress import ip_address
from pylisp.application.lispd.address_tree.base import AbstractNode
import logging


# Get the logger
logger = logging.getLogger(__name__)


class DDTReferralNode(AbstractNode):
    def __init__(self, prefix, ddt_nodes=None):
        super(DDTReferralNode, self).__init__(prefix)
        self.ddt_nodes = set()

        if ddt_nodes:
            self.update(ddt_nodes)

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.prefix, self.ddt_nodes)

    def __iter__(self):
        return iter(self.ddt_nodes)

    def __len__(self):
        return len(self.ddt_nodes)

    def add(self, ddt_node):
        ddt_node = ip_address(ddt_node)

        # Add the new node
        self.ddt_nodes.add(ddt_node)

    def clear(self):
        self.ddt_nodes = set()

    def __contains__(self, ddt_node):
        return ddt_node in self.ddt_nodes

    def copy(self):
        return self.__class__(self.prefix, self.ddt_nodes)

    def discard(self, ddt_node):
        self.ddt_nodes.discard(ddt_node)

    def remove(self, ddt_node):
        self.ddt_nodes.remove(ddt_node)

    def update(self, ddt_nodes):
        with self.lock:
            for ddt_node in ddt_nodes:
                self.add(ddt_node)
