'''
Created on 9 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, BitStream, Bits
from ipaddress import IPv4Address
from pylisp.packet.ip import protocol_registry
from pylisp.packet.ip.protocol import Protocol
from pylisp.utils import checksum
import math
import numbers


class IPv4Packet(Protocol):
    '''
    Minimal IPv4 implementation to use in LISP Encapsulated Control Messages.
    Options are not interpreted.
    '''

    header_type = 4
    version = 4

    def __init__(self, tos=0, identification=0, dont_fragment=False,
                 more_fragments=False, fragment_offset=0, ttl=0, protocol=0,
                 source=None, destination=None, options='', payload='',
                 next_header=None):
        '''
        Constructor
        '''
        # Call superclass
        super(IPv4Packet, self).__init__(next_header=next_header or protocol,
                                         payload=payload)

        # Next-header and protocol can't conflict. Protocol is the official
        # name, but next_header is used for compatibility with the other
        # headers. They use the same name/number space anyway.
        if next_header is not None and protocol != 0 \
        and next_header != protocol:
            raise ValueError("Conflicting next_header and protocol given")

        # Set defaults
        self.tos = tos
        self.identification = identification
        self.dont_fragment = dont_fragment
        self.more_fragments = more_fragments
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.source = source
        self.destination = destination
        self.options = options

    # Protocol is an alias for next-header
    @property
    def protocol(self):
        return self.next_header

    @protocol.setter
    def protocol(self, protocol):
        self.next_header = protocol

    def is_fragmented(self):
        return self.more_fragments or self.fragment_offset != 0

    def get_final_payload(self):
        return (self.protocol, self.payload)

    def sanitize(self):
        '''
        Check if the current settings conform to the RFC and fix where possible
        '''
        # Let the parent do its stuff
        super(IPv4Packet, self).sanitize()

        # Check the version
        if self.version != 4:
            raise ValueError("Protocol version must be 4")

        # Treat type-of-service as an 8-bit unsigned integer. Future versions
        # of this code may implement methods to treat it as DSCP+ECN
        if not isinstance(self.tos, numbers.Integral) \
        or self.tos < 0 \
        or self.tos >= 2 ** 8:
            raise ValueError('Invalid type of service')

        # Identification: An identifying value assigned by the sender to aid in
        # assembling the fragments of a datagram.
        if not isinstance(self.identification, numbers.Integral) \
        or self.identification < 0 \
        or self.identification >= 2 ** 16:
            raise ValueError('Invalid fragment identification')

        # An internet datagram can be marked "don't fragment."  Any internet
        # datagram so marked is not to be internet fragmented under any
        # circumstances.  If internet datagram marked don't fragment cannot be
        # delivered to its destination without fragmenting it, it is to be
        # discarded instead.
        if not isinstance(self.dont_fragment, bool):
            raise ValueError("Don't fragment flag must be a boolean")

        # The More Fragments flag bit (MF) is set if the datagram is not the
        # last fragment.  The Fragment Offset field identifies the fragment
        # location, relative to the beginning of the original unfragmented
        # datagram.  Fragments are counted in units of 8 octets.  The
        # fragmentation strategy is designed so than an unfragmented datagram
        # has all zero fragmentation information (MF = 0, fragment offset =
        # 0).  If an internet datagram is fragmented, its data portion must be
        # broken on 8 octet boundaries.
        if not isinstance(self.more_fragments, bool):
            raise ValueError('More fragments flag must be a boolean')

        # Fragment offset: This field indicates where in the datagram this
        # fragment belongs. The fragment offset is measured in units of 8
        # octets (64 bits).  The first fragment has offset zero.
        if not isinstance(self.fragment_offset, numbers.Integral) \
        or self.fragment_offset < 0 \
        or self.fragment_offset >= 2 ** 13:
            raise ValueError('Invalid fragment offset')

        # Check for don't-fragment combined with a fragment offset
        if self.dont_fragment and self.fragment_offset > 0:
            raise ValueError("A packet marked don't fragment can't have "
                             "a fragment-offset")

        # Check that the TTL is correct
        if not isinstance(self.ttl, numbers.Integral) \
        or self.ttl < 0 \
        or self.ttl >= 2 ** 8:
            raise ValueError('Invalid TTL')

        # Check the source and destination addresses
        if not isinstance(self.source, IPv4Address):
            raise ValueError('Source address must be IPv4')

        if not isinstance(self.destination, IPv4Address):
            raise ValueError('Destination address must be IPv4')

    @classmethod
    def from_bytes(cls, bitstream, decode_payload=True):
        '''
        Parse the given packet and update properties accordingly
        '''
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Read the version
        version = bitstream.read('uint:4')
        if version != packet.version:
            raise ValueError('Provided bytes do not contain an IPv4 packet')

        # Read the header length
        ihl = bitstream.read('uint:4')
        if ihl < 5:
            raise ValueError('Invalid IPv4 header length')

        # Now that we know the length of the header we store it to be able
        # to easily recalculate the header checksum later
        remaining_header_bits = (ihl * 32) - 8
        header = (BitStream('uint:4=4, uint:4=%d' % ihl) +
                  bitstream.peek(remaining_header_bits))

        # Read the type of service
        packet.tos = bitstream.read('uint:8')

        # Read the total length
        total_length = bitstream.read('uint:16')
        if total_length < ihl * 4:
            raise ValueError('Total length is shorter than the header')

        # Read the identification
        packet.identification = bitstream.read('uint:16')

        # Read the flags
        (reserved,
         packet.dont_fragment,
         packet.more_fragments) = bitstream.readlist('3*bool')

        if reserved:
            raise ValueError('Reserved flag must be 0')

        # Read the fragment offset
        packet.fragment_offset = bitstream.read('uint:13')

        # Read the TTL
        packet.ttl = bitstream.read('uint:8')

        # Read the protocol number
        packet.protocol = bitstream.read('uint:8')

        # Read the header checksum
        header_checksum = bitstream.read('uint:16')

        # Set the checksum bits in the header to 0 and re-calculate
        header[80:96] = BitStream(16)
        my_checksum = checksum.ones_complement(header.bytes)

        if my_checksum != header_checksum:
            raise ValueError('Header checksum does not match')

        # Read the source and destination addresses
        packet.source = IPv4Address(bitstream.read('uint:32'))
        packet.destination = IPv4Address(bitstream.read('uint:32'))

        # Read the options
        option_len = (ihl - 5) * 4
        packet.options = bitstream.read('bytes:%d' % option_len)

        # And the rest is payload
        payload_bytes = (total_length) - (ihl * 4)
        packet.payload = bitstream.read('bytes:%d' % payload_bytes)

        if decode_payload:
            payload_class = protocol_registry.get_type_class(packet.protocol)
            if payload_class:
                packet.payload = payload_class.from_bytes(packet.payload)

        # There should be no remaining bits
        if bitstream.pos != bitstream.len:
            raise ValueError('Bits remaining after processing packet')

        # Verify that the properties make sense
        packet.sanitize()

        return packet

    def to_bytes(self):
        '''
        Create bytes from properties
        '''
        # Verify that the properties make sense
        self.sanitize()

        # Write the version
        bitstream = BitStream('uint:4=%d' % self.version)

        # Write the header length
        options_len = math.ceil(len(self.options) / 4.0)
        bitstream += BitStream('uint:4=%d' % (5 + options_len))

        # Write the type of service
        bitstream += BitStream('uint:8=%d' % self.tos)

        # Write the total length
        payload_bytes = bytes(self.payload)
        total_length = 20 + len(payload_bytes)
        bitstream += BitStream('uint:16=%d' % total_length)

        # Write the identification
        bitstream += BitStream('uint:16=%d' % self.identification)

        # Write the flags
        bitstream += BitStream('bool=False, bool=%d, '
                               'bool=%d' % (self.dont_fragment,
                                            self.more_fragments))

        # Write the fragment offset
        bitstream += BitStream('uint:13=%d' % self.fragment_offset)

        # Write the TTL
        bitstream += BitStream('uint:8=%d' % self.ttl)

        # Write the protocol number
        bitstream += BitStream('uint:8=%d' % self.protocol)

        # Write the header checksum as 0 for now, we calculate it later
        bitstream += BitStream('uint:16=0')

        # Write the source and destination addresses
        bitstream += BitStream('uint:32=%d, '
                               'uint:32=%d' % (int(self.source),
                                               int(self.destination)))

        # Add the options
        bitstream += BitStream(bytes=self.options)
        padding_len = (4 - (len(self.options) % 4)) % 4
        bitstream += BitStream(padding_len * 8)

        # Calculate the header checksum and fill it in
        my_checksum = checksum.ones_complement(bitstream.bytes)
        bitstream[80:96] = BitStream('uint:16=%d' % my_checksum)

        return bitstream.bytes + payload_bytes


# Register this header type
protocol_registry.register_type_class(IPv4Packet)
