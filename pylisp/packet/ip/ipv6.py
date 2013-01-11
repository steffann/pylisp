'''
Created on 9 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, BitStream
from IPy import IP
from abc import ABCMeta, abstractmethod
import math


class IPv6Packet(object):
    '''
    Minimal IPv4 implementation to use in LISP Encapsulated Control Messages.
    Options are not supported, will be dropped on input and never generated on
    output.
    '''

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

    def __repr__(self):
        # This works as long as we accept all properties as paramters in the
        # constructor
        params = ['%s=%r' % (k, v) for k, v in self.__dict__.iteritems()]
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(params))

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
        payload_length = len(self.payload)
        bitstream += BitStream('uint:16=%d' % payload_length)

        # Write the next header type
        bitstream += BitStream('uint:8=%d' % self.next_header)

        # Write the hop limit
        bitstream += BitStream('uint:8=%d' % self.hop_limit)

        # Write the source and destination addresses
        bitstream += BitStream('uint:128=%d, '
                               'uint:128=%d' % (self.source.ip,
                                                self.destination.ip))

        # Determine payload
        payload = self.payload
        if hasattr(payload, 'to_bytes'):
            payload = payload.to_bytes()

        return bitstream.bytes + payload


class IPv6ExtensionHeader(object):
    __metaclass__ = ABCMeta

    header_type = 0

    @abstractmethod
    def __init__(self, next_header=0, payload=''):
        '''
        Constructor
        '''
        self.next_header = next_header
        self.payload = payload

    def __repr__(self):
        # This works as long as we accept all properties as paramters in the
        # constructor
        params = ['%s=%r' % (k, v) for k, v in self.__dict__.iteritems()]
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(params))

    @abstractmethod
    def sanitize(self):
        '''
        Check and optionally fix properties
        '''

    @classmethod
    @abstractmethod
    def from_bytes(cls, bitstream):
        '''
        Parse the given packet and update properties accordingly
        '''

    @abstractmethod
    def to_bytes(self):
        '''
        Create bytes from properties
        '''


class IPv6HopByHopOptionsHeader(IPv6ExtensionHeader):
    header_type = 0

    def __init__(self, next_header=0, payload='', options=''):
        super(IPv6HopByHopOptionsHeader, self) \
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

        # Determine payload
        payload = self.payload
        if hasattr(payload, 'to_bytes'):
            payload = payload.to_bytes()

        return bitstream.bytes + payload


class IPv6RoutingHeader(IPv6ExtensionHeader):
    header_type = 43

    def __init__(self, next_header=0, payload='', routing_type=0,
                 segments_left=0, data=''):
        super(IPv6RoutingHeader, self) \
            .__init__(next_header=next_header,
                      payload=payload)

        self.routing_type = routing_type
        self.segments_left = segments_left
        self.data = data

    def sanitize(self):
        '''
        Check and optionally fix properties
        '''

    @classmethod
    def from_bytes(cls, bitstream):
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            bitstream = ConstBitStream(bytes=bitstream)

        # Read the next header type
        packet.next_header = bitstream.read('uint:8')

        # Read the header length, given in multiples of 8 octets
        header_length = bitstream.read('uint:8') + 1

        # Read the routing type
        packet.routing_type = bitstream.read('uint:8')

        # Read the segments left
        packet.segments_left = bitstream.read('uint:8')

        # Read the data
        data_length = (header_length * 8) - 4
        packet.data = bitstream.read('bytes:%d' % data_length)

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

        # Add the routing type
        bitstream += BitStream('uint:8=%d' % self.routing_type)

        # Add the segments left
        bitstream += BitStream('uint:8=%d' % self.segments_left)

        # Add the data
        bitstream += BitStream(bytes=self.data)
        padding_len = (8 - (header_length_unpadded % 8)) % 8
        bitstream += BitStream(padding_len * 8)

        # Determine payload
        payload = self.payload
        if hasattr(payload, 'to_bytes'):
            payload = payload.to_bytes()

        return bitstream.bytes + payload


class IPv6FragmentHeader(IPv6ExtensionHeader):
    header_type = 43

    def __init__(self, next_header=0, payload='', fragment_offset=0,
                 more_fragments=False, identification=0):
        super(IPv6RoutingHeader, self) \
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

        # Add the routing type
        bitstream += BitStream('uint:8=%d' % self.routing_type)

        # Add the segments left
        bitstream += BitStream('uint:8=%d' % self.segments_left)

        # Add the data
        bitstream += BitStream(bytes=self.data)
        padding_len = (8 - (header_length_unpadded % 8)) % 8
        bitstream += BitStream(padding_len * 8)

        # Determine payload
        payload = self.payload
        if hasattr(payload, 'to_bytes'):
            payload = payload.to_bytes()

        return bitstream.bytes + payload
