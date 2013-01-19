'''
Created on 11 jan. 2013

@author: sander
'''
from bitstring import BitStream, ConstBitStream, Bits
from pylisp.packet.ip import protocol_registry
from pylisp.packet.ip.ipv6.base import IPv6ExtensionHeader
import math


class IPv6FragmentHeader(IPv6ExtensionHeader):
    header_type = 44

    def __init__(self, next_header=0, payload='', fragment_offset=0,
                 more_fragments=False, identification=0):
        super(IPv6FragmentHeader, self) \
            .__init__(next_header=next_header,
                      payload=payload)

        self.fragment_offset = fragment_offset
        self.more_fragments = more_fragments
        self.identification = identification

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

        # Skip over reserved bits
        bitstream.read(8)

        # Read the fragment offset
        packet.fragment_offset = bitstream.read('uint:13')

        # Skip over reserved bits
        bitstream.read(2)

        # Read the more fragments
        packet.more_fragments = bitstream.read('bool')

        # Read the identification
        packet.identification = bitstream.read('uint:32')

        # And the rest is payload
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

        # Write the next header type
        bitstream = BitStream('uint:8=%d' % self.next_header)

        # Write the header length
        header_length_unpadded = len(self.data) + 4
        header_length = math.ceil(header_length_unpadded / 8.0)
        bitstream += BitStream('uint:8=%d' % (header_length - 1))

        # Add the reserved bits
        bitstream += BitStream(8)

        # Add the fragment offset
        bitstream += BitStream('uint:13=%d' % self.fragment_offset)

        # Add the reserved bits
        bitstream += BitStream(2)

        # Add the flags
        bitstream += BitStream('bool=%d' % self.more_fragments)

        # Add the identification
        bitstream += BitStream('uint:32=%d' % self.identification)

        return bitstream.bytes + bytes(self.payload)


# Register this header type
protocol_registry.register_type_class(IPv6FragmentHeader)
