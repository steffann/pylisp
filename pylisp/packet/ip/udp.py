'''
Created on 9 jan. 2013

@author: sander
'''
from bitstring import BitStream, ConstBitStream, Bits
from pylisp.packet.ip.protocol import Protocol
from pylisp.utils import checksum
from pylisp.packet.ip import protocol_registry


class UDPMessage(Protocol):
    header_type = 17

    def __init__(self, source_port=0, destination_port=0, checksum=0,
                 payload=''):
        self.source_port = source_port
        self.destination_port = destination_port
        self.checksum = checksum
        self.payload = payload

    def sanitize(self):
        '''
        Check if the current settings conform to the RFC and fix where possible
        '''
        # TODO: everything...

    def generate_pseudo_header(self, source, destination):
        # Calculate the length of the UDP layer
        udp_length = 8 + len(bytes(self.payload))

        if source.version() == 4 and destination.version() == 4:
            # Generate an IPv4 pseudo-header
            header = BitStream('uint:32=%d, '
                               'uint:32=%d, '
                               'uint:16=17, '
                               'uint:16=%d' % (source.ip,
                                               destination.ip,
                                               udp_length))

        elif source.version() == 6 and destination.version() == 6:
            # Generate an IPv6 pseudo-header
            header = BitStream('uint:128=%d, '
                               'uint:128=%d, '
                               'uint:32=%d, '
                               'uint:32=17' % (source.ip,
                                               destination.ip,
                                               udp_length))
        else:
            raise ValueError('Source and destination must belong to the same '
                             'IP version')

        # Return the header bytes
        return header.bytes

    def calculate_checksum(self, source, destination):
        # Calculate the pseudo-header for the checksum calculation
        pseudo_header = self.generate_pseudo_header(source, destination)

        # Remember the current checksum, generate a message and restore the
        # original checksum
        old_checksum = self.checksum
        self.checksum = 0
        message = self.to_bytes()
        self.checksum = old_checksum

        # Calculate the checksum
        return checksum.ones_complement(pseudo_header + message)

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

        # Read the source and destination ports
        (packet.source_port,
         packet.destination_port) = bitstream.readlist('2*uint:16')

        # Store the length
        length = bitstream.read('uint:16')
        if length < 8:
            raise ValueError('Invalid UDP length')

        # Read the checksum
        packet.checksum = bitstream.read('uint:16')

        # And the rest is payload
        payload_bytes = length - 8
        packet.payload = bitstream.read('bytes:%d' % payload_bytes)

        # LISP-specific handling
        if packet.source_port == 4341 or packet.destination_port == 4341:
            # Payload is a LISP data packet
            from pylisp.packet.lisp.data import LISPDataPacket
            packet.payload = LISPDataPacket.from_bytes(packet.payload)
        elif packet.source_port == 4342 or packet.destination_port == 4342:
            # Payload is a LISP control message
            from pylisp.packet.lisp.control.base import LISPControlMessage
            packet.payload = LISPControlMessage.from_bytes(packet.payload)

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

        # Write the source and destination ports
        bitstream = BitStream('uint:16=%d, '
                              'uint:16=%d' % (self.source_port,
                                              self.destination_port))

        # Write the length
        payload_bytes = bytes(self.payload)
        length = len(payload_bytes) + 8
        bitstream += BitStream('uint:16=%d' % length)

        # Write the checksum
        bitstream += BitStream('uint:16=%d' % self.checksum)

        return bitstream.bytes + payload_bytes

# Register this header type
protocol_registry.register_type_class(UDPMessage)
