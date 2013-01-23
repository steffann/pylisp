'''
Created on 15 jan. 2013

@author: sander
'''

from IPy import IP
from pylisp.packet.lisp.control import EncapsulatedControlMessage, \
    MapRequestMessage, MapNotifyMessage, MapReplyMessage, MapReferralMessage, \
    MapRegisterMessage
import logging
import socket


# Get the logger
logger = logging.getLogger(__name__)


class MessageHandler(object):
    def __repr__(self):
        # This works as long as we accept all properties as paramters in the
        # constructor
        params = ['%s=%r' % (key, value)
                  for key, value in self.__dict__.iteritems()
                  if not key.startswith('_')]
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(params))

    def send_message(self, message, my_sockets, destinations, port=4342):
        # Find an appropriate destination
        for destination in destinations:
            destination = IP(destination)
            dest_family = (destination.version() == 4
                           and socket.AF_INET
                           or socket.AF_INET6)
            for sock in my_sockets:
                if sock.family == dest_family:
                    addr = (destination.strNormal(False), port)
                    data = bytes(message)
                    logger.debug("Hander %r sent reply %r", self, message)
                    logger.debug("Sending %d bytes to %r", len(data), addr)
                    sent = sock.sendto(data, addr)
                    return (sent == len(data))

    def handle(self, received_message, my_sockets):
        """
        Handle a LISP message. The default handle method determines the type
        of message and delegates it to the more specific method
        """
        if isinstance(received_message.message, MapRequestMessage):
            # A map-request message
            return self.handle_map_request(received_message, my_sockets)

        elif isinstance(received_message.message, MapReplyMessage):
            # A map-reply message
            return self.handle_map_reply(received_message, my_sockets)

        elif isinstance(received_message.message, MapRegisterMessage):
            # A map-register message
            return self.handle_map_register(received_message, my_sockets)

        elif isinstance(received_message.message, MapNotifyMessage):
            # A map-notify message
            return self.handle_map_notify(received_message, my_sockets)

        elif isinstance(received_message.message, MapReferralMessage):
            # A map-referral message
            return self.handle_map_referral(received_message, my_sockets)

        elif isinstance(received_message.message, EncapsulatedControlMessage):
            # Determine the type of ECM
            if isinstance(received_message.inner_message, MapRequestMessage):
                if received_message.message.ddt_originated:
                    # A DDT map-request message
                    return self.handle_ddt_map_request(received_message,
                                                       my_sockets)
                else:
                    # An encapsulated map-request message
                    return self.handle_enc_map_request(received_message,
                                                       my_sockets)
            else:
                logger.warning("ECM does not contain a map-request in "
                               "message %d", received_message.message_nr)
                return False
        else:
            logger.warning("Unknown content in message %d",
                           received_message.message_nr)
            return False

    def handle_map_request(self, received_message, my_sockets):
        return False

    def handle_map_reply(self, received_message, my_sockets):
        return False

    def handle_map_register(self, received_message, my_sockets):
        return False

    def handle_map_notify(self, received_message, my_sockets):
        return False

    def handle_map_referral(self, received_message, my_sockets):
        return False

    def handle_ddt_map_request(self, received_message, my_sockets):
        return False

    def handle_enc_map_request(self, received_message, my_sockets):
        return False
