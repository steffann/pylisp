'''
Created on 6 jan. 2013

@author: sander
'''
from abc import ABCMeta, abstractmethod
from bitstring import ConstBitStream, Bits
from pylisp.packet.ip.protocol import Protocol


class ControlMessage(Protocol):
    '''
    This is the abstract base class for all LISP control packets
    '''

    __metaclass__ = ABCMeta

    # Class property: which message type do we represent?
    message_type = None

    @abstractmethod
    def __init__(self):
        '''
        Constructor
        '''

    @abstractmethod
    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix them where possible.
        '''

    @classmethod
    @abstractmethod
    def from_bytes(cls, bitstream):
        '''
        Look at the type of the message, instantiate the correct class and
        let it parse the message.
        '''
        from pylisp.packet.lisp.control import type_registry

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Peek at the bitstream to see which type it is
        type_nr = bitstream.peek('uint:4')

        # Look for the right class
        type_class = type_registry.get_type_class(type_nr)
        if not type_class:
            raise ValueError("Can't handle message type {0}".format(type_nr))

        # Let the specific class handle it from now on
        return type_class.from_bytes(bitstream)

    @abstractmethod
    def to_bytes(self):
        '''
        Create bytes from properties
        '''
