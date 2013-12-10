'''
Created on 1 jun. 2013

@author: sander
'''
from ipaddress import ip_address, IPv4Address, IPv6Address
from pylisp.application.lispd.address_tree.container_node import ContainerNode
import logging


# Get the logger
logger = logging.getLogger(__name__)


class AuthContainerNode(ContainerNode):
    '''
    A ContainerNode that indicates that we are authoritative for this part of
    the address tree.
    '''
    def __init__(self, prefix, children=None, ddt_nodes=None):
        super(AuthContainerNode, self).__init__(prefix, children)

        # Are there ddt_nodes known that have the same authority?
        self.ddt_nodes = set()

        for ddt_node in ddt_nodes or []:
            if not isinstance(ddt_node, (IPv4Address, IPv6Address)):
                ddt_node = ip_address(unicode(ddt_node))

            self.ddt_nodes.add(ddt_node)
