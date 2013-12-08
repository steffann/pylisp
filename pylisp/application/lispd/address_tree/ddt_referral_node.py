'''
Created on 11 mrt. 2013

@author: sander
'''
from ipaddress import ip_address
from pylisp.application.lispd.address_tree.authoritative_container_node import AuthoritativeContainerNode
from pylisp.application.lispd.address_tree.base import AbstractNode
from pylisp.application.lispd.send_message import send_message
from pylisp.application.lispd.utils.prefix import determine_instance_id_and_afi, resolve_path
from pylisp.packet.lisp.control.locator_record import LocatorRecord
from pylisp.packet.lisp.control.map_referral import MapReferralMessage
from pylisp.packet.lisp.control.map_referral_record import MapReferralRecord
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
        for ddt_node in ddt_nodes:
            self.add(ddt_node)


def send_answer(received_message, referral):
    map_request = received_message.inner_message

    # Put it in a reply packet
    reply = MapReferralMessage(nonce=map_request.nonce,
                               records=[referral])

    # Send the reply over UDP
    send_message(message=reply,
                 my_sockets=[received_message.socket],
                 destinations=[received_message.source[0]],
                 port=received_message.source[1])


def send_referral(received_message, tree_node):
    logger.debug("Sending NODE_REFERRAL response for message %d", received_message.message_nr)

    map_request = received_message.inner_message

    locators = []
    for ddt_node in tree_node:
        locator = LocatorRecord(priority=0, weight=0,
                                m_priority=0, m_weight=0,
                                reachable=True, locator=ddt_node)
        locators.append(locator)

    referral = MapReferralRecord(ttl=1440,
                                 action=MapReferralRecord.ACT_NODE_REFERRAL,
                                 authoritative=True,
                                 eid_prefix=map_request.eid_prefixes[0],
                                 locator_records=locators)

    send_answer(received_message, referral)


def send_delegation_hole(received_message):
    logger.debug("Sending DELEGATION_HOLE response for message %d", received_message.message_nr)

    map_request = received_message.inner_message

    # We are authoritative and no matching targets, we seem to have a hole
    referral = MapReferralRecord(ttl=15,
                                 authoritative=True,
                                 action=MapReferralRecord.ACT_DELEGATION_HOLE,
                                 eid_prefix=map_request.eid_prefixes[0])

    send_answer(received_message, referral)


def send_not_authoritative(received_message):
    logger.debug("Sending NOT_AUTHORITATIVE response for message %d", received_message.message_nr)

    map_request = received_message.inner_message

    # No matching prefixes, we don't seem to be authoritative
    referral = MapReferralRecord(ttl=0,
                                 action=MapReferralRecord.ACT_NOT_AUTHORITATIVE,
                                 incomplete=True,
                                 eid_prefix=map_request.eid_prefixes[0])

    send_answer(received_message, referral)


def handle_ddt_map_request(received_message, control_plane_sockets, data_plane_sockets):
    ecm = received_message.message

    # TODO: Implement security [LISP-Security]
    if ecm.security:
        logger.error("We can't handle LISP-Security yet")
        return

    # Look up the address in the tree
    map_request = received_message.inner_message
    instance_id, afi, req_prefix = determine_instance_id_and_afi(map_request.eid_prefixes[0])
    tree_nodes = resolve_path(instance_id, afi, req_prefix)
    if not tree_nodes:
        # We are not authoritative
        send_not_authoritative(received_message)
        return

    tree_node = tree_nodes[0]
    if isinstance(tree_node, DDTReferralNode):
        # Return the delegations
        send_referral(received_message, tree_node)

    elif any([isinstance(node, AuthoritativeContainerNode) for node in tree_nodes]):
        # We are authoritative and no matching targets, we seem to have a hole
        send_delegation_hole(received_message)

    else:
        # We are not authoritative
        send_not_authoritative(received_message)
