'''
Created on 11 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, Bits
from pylisp.packet.ip import protocol_registry
from pylisp.packet.ip.ipv6.base import IPv6ExtensionHeader


class IPv6NoNextHeader(IPv6ExtensionHeader):
    header_type = 59

    def __init__(self, next_header=0, payload=''):
        super(IPv6NoNextHeader, self) \
            .__init__(next_header=next_header,
                      payload=payload)

        # No next header, ever
        self.next_header = None

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

        # Everything is payload
        remaining = bitstream[bitstream.pos:]
        packet.payload = remaining.bytes

        # Verify that the properties make sense
        packet.sanitize()

        return packet

    def to_bytes(self):
        '''
        Create bytes from properties
        '''
        # Verify that the properties make sense
        self.sanitize()

        return bytes(self.payload)

# Register this header type
protocol_registry.register_type_class(IPv6NoNextHeader)
