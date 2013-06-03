'''
Created on 23 jan. 2013

@author: sander
'''
from multiprocessing.dummy import Lock
from pylisp.packet.lisp.control import EncapsulatedControlMessage, ControlMessage
from pylisp.utils.represent import represent
import logging


# Get the logger
logger = logging.getLogger(__name__)


class ReceivedMessage(object):
    counter = 0
    counter_lock = Lock()

    def __init__(self, source, destination, message, socket, message_nr=None):

        if message_nr:
            self.message_nr = message_nr
        else:
            # Get the next number
            with ReceivedMessage.counter_lock:
                ReceivedMessage.counter += 1
                self.message_nr = ReceivedMessage.counter

        self.source = source
        self.destination = destination
        self.message = message
        self.socket = socket

        # Sanity check
        if not isinstance(self.message, ControlMessage):
            raise ValueError("Non-LISP message detected: %r" % self.message)

        # Decapsulate ECM, we need this data often
        if isinstance(self.message, EncapsulatedControlMessage):
            try:
                self.udp_layer = self.message.get_udp()
                self.inner_message = self.udp_layer.get_lisp_control_message()
            except Exception:
                raise ValueError("ECM has invalid content in message %d",
                                 self.message_nr)

            # Check the UDP ports
            if self.udp_layer.destination_port != 4342:
                raise ValueError("ECM not sent to UDP port 4342 in message %d",
                                 self.message_nr)
        else:
            self.udp_layer = None
            self.inner_message = None

    def __repr__(self):
        return represent(self.__class__.__name__, self.__dict__,
                         ('udp_layer', 'inner_message'))
