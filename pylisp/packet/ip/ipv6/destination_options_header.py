'''
Created on 11 jan. 2013

@author: sander
'''
from bitstring import BitStream, ConstBitStream, Bits
from pylisp.packet.ip import protocol_registry
from pylisp.packet.ip.ipv6.base import IPv6ExtensionHeader
import math


class IPv6DestinationOptionsHeader(IPv6ExtensionHeader):
    header_type = 60

    def __init__(self, next_header=0, payload='', options=''):
        super(IPv6DestinationOptionsHeader, self) \
            .__init__(next_header=next_header,
                      payload=payload)

        self.options = options

    def sanitize(self):
        '''
        Check and optionally fix properties
        '''

    @classmethod
    def from_bytes(cls, bitstream):
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Read the next header type
        packet.next_header = bitstream.read('uint:8')

        # Read the header length, given in multiples of 8 octets
        header_length = bitstream.read('uint:8') + 1

        # Read the options
        options_length = (header_length * 8) - 2
        packet.options = bitstream.read('bytes:%d' % options_length)

        # And the rest is payload
        remaining = bitstream[bitstream.pos:]
        packet.payload = remaining.bytes

        payload_class = protocol_registry.get_type_class(packet.next_header)
        if payload_class:
            packet.payload = payload_class.from_bytes(packet.payload)

        # Verify that the properties make sense
        packet.sanitize()

        return packet

    def to_bytes(self):
        '''
        Create bytes from properties
        '''
        # Verify that the properties make sense
        self.sanitize()

        # Write the next header type
        bitstream = BitStream('uint:8=%d' % self.next_header)

        # Write the header length
        header_length_unpadded = len(self.options) + 2
        header_length = math.ceil(header_length_unpadded / 8.0)
        bitstream += BitStream('uint:8=%d' % (header_length - 1))

        # Add the options
        bitstream += BitStream(bytes=self.options)
        padding_len = (8 - (header_length_unpadded % 8)) % 8
        bitstream += BitStream(padding_len * 8)

        return bitstream.bytes + bytes(self.payload)


# Register this header type
protocol_registry.register_type_class(IPv6DestinationOptionsHeader)
