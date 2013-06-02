'''
Created on 2 jun. 2013

@author: sander
'''

from ipaddress import IPv4Network, IPv4Address, IPv6Network, IPv6Address
from pylisp.application.lispd import settings
from pylisp.application.lispd.address_tree import AuthoritativeContainerNode, DDTReferralNode
from pylisp.application.lispd.send_message import send_message
from pylisp.packet.lisp.control import LocatorRecord, MapReferralMessage, MapReferralRecord
from pylisp.utils.lcaf import LCAFInstanceAddress
import logging


# Get the logger
logger = logging.getLogger(__name__)


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


def handle_ddt_map_request(received_message, my_sockets):
    logger.debug("Handling message %d as a DDT Map-Request", received_message.message_nr)

    ecm = received_message.message
    map_request = received_message.inner_message
    req_prefix = map_request.eid_prefixes[0]
    if not isinstance(req_prefix, LCAFInstanceAddress):
        if not isinstance(req_prefix, (IPv4Network, IPv4Address, IPv6Network, IPv6Address)):
            raise ValueError("Unexpected EID prefix %r in message %d", req_prefix, received_message.message_nr)
        req_prefix = LCAFInstanceAddress(instance_id=0, address=req_prefix)

    # TODO: Implement security [LISP-Security]
    if ecm.security:
        logger.error("We can't handle LISP-Security yet")
        return False

    # Look up the address in the tree
    instance = settings.config.INSTANCES.get(req_prefix.instance_id)
    if instance is None:
        send_not_authoritative(received_message)
        return False

    afi = isinstance(req_prefix.address, (IPv4Address, IPv4Network)) and 1 or 2
    tree_nodes = instance[afi].resolve_path(req_prefix.address)
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

    return True
