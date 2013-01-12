'''
Created on 9 jan. 2013

@author: sander
'''
from IPy import IP
from bitstring import ConstBitStream, BitStream, Bits
from pylisp.packet.ip.protocol import Protocol
from pylisp.packet.ip import protocol_registry


class IPv6Packet(Protocol):
    '''
    Minimal IPv4 implementation to use in LISP Encapsulated Control Messages.
    Options are not supported, will be dropped on input and never generated on
    output.
    '''

    header_type = 41
    version = 6

    def __init__(self, traffic_class=0, flow_label=0, next_header=0,
                 hop_limit=0, source=None, destination=None, payload=''):
        '''
        Constructor
        '''
        # Set defaults
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.source = source
        self.destination = destination
        self.payload = payload

    def get_final_payload(self):
        next_header = self.next_header
        payload = self.payload

        while isinstance(payload, IPv6ExtensionHeader) \
        and payload.next_header is not None:
            next_header = payload.next_header
            payload = payload.payload

        return (next_header, payload)

    def sanitize(self):
        '''
        Check if the current settings conform to the RFC and fix where possible
        '''
        # TODO: everything...

    @classmethod
    def from_bytes(cls, bitstream):
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
            raise ValueError('Provided bytes do not contain an IPv6 packet')

        # Read the traffic class
        packet.traffic_class = bitstream.read('uint:8')

        # Read the flow label
        packet.flow_label = bitstream.read('uint:20')

        # Read the payload length
        payload_length = bitstream.read('uint:16')

        # Read the next header type
        packet.next_header = bitstream.read('uint:8')

        # Read the hop limit
        packet.hop_limit = bitstream.read('uint:8')

        # Read the source and destination addresses
        packet.source = IP(bitstream.read('uint:128'))
        packet.destination = IP(bitstream.read('uint:128'))

        # And the rest is payload
        packet.payload = bitstream.read('bytes:%d' % payload_length)

        payload_class = protocol_registry.get_type_class(packet.next_header)
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

        # Write the traffic class
        bitstream += BitStream('uint:8=%d' % self.traffic_class)

        # Write the flow label
        bitstream += BitStream('uint:20=%d' % self.flow_label)

        # Write the payload length
        payload_bytes = bytes(self.payload)
        payload_length = len(payload_bytes)
        bitstream += BitStream('uint:16=%d' % payload_length)

        # Write the next header type
        bitstream += BitStream('uint:8=%d' % self.next_header)

        # Write the hop limit
        bitstream += BitStream('uint:8=%d' % self.hop_limit)

        # Write the source and destination addresses
        bitstream += BitStream('uint:128=%d, '
                               'uint:128=%d' % (self.source.ip,
                                                self.destination.ip))

        return bitstream.bytes + payload_bytes


class IPv6ExtensionHeader(Protocol):
    '''
    IPv6 extension headers use the same number space as protocols
    '''


# Register this header type
protocol_registry.register_type_class(IPv6Packet)
