'''
Created on 19 jan. 2013

@author: sander
'''
from pylisp.application.lispd.message_handler import LISPMessageHandler
from pylisp.packet.ip.udp import UDPMessage
from pylisp.packet.lisp.control import LISPEncapsulatedControlMessage, \
    LISPMapReferralMessage, LISPMapReferralRecord, LISPMapRequestMessage
import logging
from pylisp.utils.lcaf.instance_address import LCAFInstanceAddress


# Get the logger
logger = logging.getLogger(__name__)


class LISPDDTMessageHandler(LISPMessageHandler):
    def __init__(self, data=None):
        self.data = data or []

    def handle_ddt_map_request(self, ecm, udp, message, source, sockets):
        assert isinstance(ecm, LISPEncapsulatedControlMessage)
        assert isinstance(udp, UDPMessage)
        assert isinstance(message, LISPMapRequestMessage)

        if ecm.security:
            logger.error("This handler can't handle security")
            return False

        for prefix, dummy in self.data:
            req_prefix = message.eid_prefixes[0]
            if isinstance(req_prefix, LCAFInstanceAddress):
                req_prefix = req_prefix.address

            if req_prefix in prefix:
                logging.info("Matched DDT prefix %r", prefix)

                # TODO: handle

                # No matching content, we seem to have hot a hole
                # TODO: we assume the whole prefix is a hole, FIX!
                hole = LISPMapReferralRecord.ACT_DELEGATION_HOLE
                eid_prefix = LCAFInstanceAddress(0, prefix)
                referral = LISPMapReferralRecord(ttl=15,
                                                 authoritative=True,
                                                 action=hole,
                                                 eid_prefix=eid_prefix)
                reply = LISPMapReferralMessage(nonce=message.nonce,
                                               records=[referral])

                # Send the reply over UDP
                self.send_message(message=reply, sockets=sockets,
                                  destinations=message.itr_rlocs,
                                  port=udp.source_port)
                return True

        # No matching prefixes, we don't seem to be authoritative
        not_auth = LISPMapReferralRecord.ACT_NOT_AUTHORITATIVE
        referral = LISPMapReferralRecord(ttl=0,
                                         action=not_auth,
                                         incomplete=True,
                                         eid_prefix=message.eid_prefixes[0])
        reply = LISPMapReferralMessage(nonce=message.nonce,
                                       records=[referral])

        # Send the reply over UDP
        self.send_message(message=reply, sockets=sockets,
                          destinations=message.itr_rlocs, port=udp.source_port)
        return True
