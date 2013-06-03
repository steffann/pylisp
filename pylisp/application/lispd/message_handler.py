'''
Created on 15 jan. 2013

@author: sander
'''

from pylisp.application.lispd.ddt_handler import handle_ddt_map_request
from pylisp.application.lispd.etr_handler import handle_map_notify, handle_map_request
from pylisp.packet.lisp.control import (EncapsulatedControlMessage, MapNotifyMessage, MapReferralMessage,
    MapRegisterMessage, MapReplyMessage, MapRequestMessage)
import logging


# Get the logger
logger = logging.getLogger(__name__)


def handle_message(received_message, my_sockets):
    """
    Handle a LISP message. The default handle method determines the type
    of message and delegates it to the more specific method
    """
    logger.debug("Handling message %d from %r: %r",
                 received_message.message_nr,
                 received_message.source,
                 received_message.message)

    try:
        if isinstance(received_message.message, MapRequestMessage):
            # A map-request message
            handle_map_request(received_message, my_sockets)

        elif isinstance(received_message.message, MapReplyMessage):
            # A map-reply message
            handle_map_reply(received_message, my_sockets)

        elif isinstance(received_message.message, MapNotifyMessage):
            # A map-notify message (subclass of MapRegisterMessage, so put above it!)
            handle_map_notify(received_message, my_sockets)

        elif isinstance(received_message.message, MapRegisterMessage):
            # A map-register message
            handle_map_register(received_message, my_sockets)

        elif isinstance(received_message.message, MapReferralMessage):
            # A map-referral message
            handle_map_referral(received_message, my_sockets)

        elif isinstance(received_message.message, EncapsulatedControlMessage):
            # Determine the type of ECM
            if isinstance(received_message.inner_message, MapRequestMessage):
                if received_message.message.ddt_originated:
                    # A DDT map-request message
                    handle_ddt_map_request(received_message, my_sockets)
                else:
                    # An encapsulated map-request message
                    handle_enc_map_request(received_message, my_sockets)
            else:
                logger.warning("ECM does not contain a map-request in message %d", received_message.message_nr)
        else:
            logger.warning("Unknown content in message %d", received_message.message_nr)
    except:
        logger.exception("Unexpected exception while handling message %d", received_message.message_nr)


def handle_map_reply(received_message, my_sockets):
    pass


def handle_map_register(received_message, my_sockets):
    pass


def handle_map_referral(received_message, my_sockets):
    pass


def handle_enc_map_request(received_message, my_sockets):
    pass
