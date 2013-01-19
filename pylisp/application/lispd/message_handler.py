'''
Created on 15 jan. 2013

@author: sander
'''

from pylisp.packet.lisp.control.encapsulated_control_message import \
    LISPEncapsulatedControlMessage
from pylisp.packet.lisp.control.map_notify import LISPMapNotifyMessage
from pylisp.packet.lisp.control.map_referral import LISPMapReferralMessage
from pylisp.packet.lisp.control.map_register import LISPMapRegisterMessage
from pylisp.packet.lisp.control.map_reply import LISPMapReplyMessage
from pylisp.packet.lisp.control.map_request import LISPMapRequestMessage
import logging
import socket
from IPy import IP


# Get the logger
logger = logging.getLogger(__name__)


class LISPMessageHandler(object):
    def __repr__(self):
        # This works as long as we accept all properties as paramters in the
        # constructor
        params = ['%s=%r' % (k, v) for k, v in self.__dict__.iteritems()]
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(params))

    def send_message(self, message, sockets, destinations, port=4342):
        # Find an appropriate destination
        for destination in destinations:
            destination = IP(destination)
            dest_family = (destination.version() == 4
                           and socket.AF_INET
                           or socket.AF_INET6)
            for sock in sockets:
                if sock.family == dest_family:
                    addr = (destination.strNormal(False), port)
                    data = bytes(message)
                    logging.debug("Hander %r sent reply %r", self, message)
                    logging.debug("Sending %d bytes to %r", len(data), addr)
                    sent = sock.sendto(data, addr)
                    return (sent == len(data))

    def handle(self, message, source, sockets):
        """
        Handle a LISP message. The default handle method determines the type
        of message and delegates it to the more specific method
        """
        if isinstance(message, LISPMapRequestMessage):
            # A map-request message
            return self.handle_map_request(message=message,
                                           source=source,
                                           sockets=sockets)

        elif isinstance(message, LISPMapReplyMessage):
            # A map-reply message
            return self.handle_map_reply(message=message,
                                         source=source,
                                         sockets=sockets)

        elif isinstance(message, LISPMapRegisterMessage):
            # A map-register message
            return self.handle_map_register(message=message,
                                            source=source,
                                            sockets=sockets)

        elif isinstance(message, LISPMapNotifyMessage):
            # A map-notify message
            return self.handle_map_notify(message=message,
                                          source=source,
                                          sockets=sockets)

        elif isinstance(message, LISPMapReferralMessage):
            # A map-referral message
            return self.handle_map_referral(message=message,
                                            source=source,
                                            sockets=sockets)

        elif isinstance(message, LISPEncapsulatedControlMessage):
            try:
                assert isinstance(message, LISPEncapsulatedControlMessage)
                udp = message.get_udp()
                ctrl_message = udp.get_lisp_control_message()
            except Exception, e:
                logging.warning("ECM has invalid content")
                return False

            # Check the UDP ports
            if udp.destination_port != 4342:
                logger.warning("ECM not sent to UDP port 4342: %r",
                               message)
                return False

            # Determine the type of ECM
            if isinstance(ctrl_message, LISPMapRequestMessage):
                if message.ddt_originated:
                    # A DDT map-request message
                    return self.handle_ddt_map_request(ecm=message,
                                                       udp=udp,
                                                       message=ctrl_message,
                                                       source=source,
                                                       sockets=sockets)
                else:
                    # An encapsulated map-request message
                    return self.handle_encap_map_request(ecm=message,
                                                         udp=udp,
                                                         message=ctrl_message,
                                                         source=source,
                                                         sockets=sockets)
            else:
                logging.warning("ECM does not contain a map-request: %r",
                                ctrl_message)
                return False
        else:
            logging.warning("Unknown message: %r", message)
            return False

    def handle_map_request(self, message, source, sockets):
        return False

    def handle_map_reply(self, message, source, sockets):
        return False

    def handle_map_register(self, message, source, sockets):
        return False

    def handle_map_notify(self, message, source, sockets):
        return False

    def handle_map_referral(self, message, source, sockets):
        return False

    def handle_ddt_map_request(self, ecm, udp, message, source, sockets):
        return False

    def handle_encap_map_request(self, ecm, udp, message, source, sockets):
        return False
