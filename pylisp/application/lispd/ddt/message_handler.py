'''
Created on 19 jan. 2013

@author: sander
'''
from IPy import IP
from abc import ABCMeta, abstractmethod
from pylisp.application.lispd.message_handler import MessageHandler
from pylisp.packet.lisp.control import LocatorRecord, MapReferralMessage, \
    MapReferralRecord
from pylisp.utils.lcaf.instance_address import LCAFInstanceAddress
import logging


# Get the logger
logger = logging.getLogger(__name__)


class DDTMessageHandler(MessageHandler):
    __metaclass__ = ABCMeta

    @abstractmethod
    def is_authoritative(self, req_prefix):
        assert isinstance(req_prefix, LCAFInstanceAddress)
        return False

    @abstractmethod
    def get_delegation(self, req_prefix):
        assert isinstance(req_prefix, LCAFInstanceAddress)
        return req_prefix, []

    def handle_ddt_map_request(self, received_message, my_sockets):
        ecm = received_message.message
        map_request = received_message.inner_message
        req_prefix = map_request.eid_prefixes[0]
        if not isinstance(req_prefix, LCAFInstanceAddress):
            if not isinstance(req_prefix, IP):
                raise ValueError("Unexpected EID prefix %r in message %d",
                                 req_prefix, received_message.message_nr)
            req_prefix = LCAFInstanceAddress(instance_id=0, address=req_prefix)

        # TODO: Implement security
        if ecm.security:
            logger.error("This handler can't handle security")
            return False

        # Check that we are authoritative for this EID
        if not self.is_authoritative(req_prefix):
            return False

        # Get the delegation details
        eid_prefix, delegate_to = self.get_delegation(req_prefix)

        if delegate_to:
            # Return the delegations
            act_node_ref = MapReferralRecord.ACT_NODE_REFERRAL
            locators = []
            for delegate_addr in delegate_to:
                locator = LocatorRecord(priority=0, weight=0,
                                        m_priority=0, m_weight=0,
                                        reachable=True, locator=delegate_addr)
                locators.append(locator)

            referral = MapReferralRecord(ttl=1440,
                                         action=act_node_ref,
                                         authoritative=True,
                                         eid_prefix=eid_prefix,
                                         locator_records=locators)
        else:
            # No matching targets, we seem to have a hole
            act_hole = MapReferralRecord.ACT_DELEGATION_HOLE
            referral = MapReferralRecord(ttl=15,
                                         authoritative=True,
                                         action=act_hole,
                                         eid_prefix=eid_prefix)

        # Put it in a reply packet
        reply = MapReferralMessage(nonce=map_request.nonce,
                                   records=[referral])

        # Send the reply over UDP
        self.send_message(message=reply,
                          my_sockets=[received_message.socket],
                          destinations=[received_message.source[0]],
                          port=received_message.source[1])
        return True
