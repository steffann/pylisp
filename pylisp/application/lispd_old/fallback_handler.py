'''
Created on 23 jan. 2013

@author: sander
'''
from pylisp.application.lispd.message_handler import MessageHandler
from pylisp.packet.lisp.control import MapReferralMessage, MapReferralRecord


class FallbackHandler(MessageHandler):
    """
    A handler that sends NOT-AUTHORITATIVE replies for all DDT requests
    """
    def handle_ddt_map_request(self, received_message, my_sockets):
        map_request = received_message.inner_message

        # No matching prefixes, we don't seem to be authoritative
        not_auth = MapReferralRecord.ACT_NOT_AUTHORITATIVE
        referral = MapReferralRecord(ttl=0,
                                     action=not_auth,
                                     incomplete=True,
                                     eid_prefix=map_request.eid_prefixes[0])
        reply = MapReferralMessage(nonce=map_request.nonce,
                                   records=[referral])

        # Send the reply over UDP
        self.send_message(message=reply, my_sockets=[received_message.socket],
                          destinations=[received_message.source[0]],
                          port=received_message.source[1])
        return True


fallback_handler = FallbackHandler()
