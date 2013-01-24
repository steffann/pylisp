'''
Created on 7 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, BitArray, Bits
from pylisp.packet.ip import IPv4Packet, IPv6Packet
from pylisp.packet.lisp.control import type_registry, ControlMessage
from pylisp.packet.ip.udp import UDPMessage


__all__ = ['EncapsulatedControlMessage']


class EncapsulatedControlMessage(ControlMessage):
    # Class property: which message type do we represent?
    message_type = 8

    def __init__(self, security=False, ddt_originated=False, payload=''):
        '''
        Constructor
        '''
        super(EncapsulatedControlMessage, self).__init__()

        # Set defaults
        self.security = security
        self.ddt_originated = ddt_originated
        self.payload = payload

    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix them where possible.
        '''
        super(EncapsulatedControlMessage, self).sanitize()

        # S: This is the Security bit.  When set to 1 the following
        # authentication information will be appended to the end of the Map-
        # Reply.  The detailed format of the Authentication Data Content is
        # for further study.
        if not isinstance(self.security, bool):
            raise ValueError('Security flag must be a boolean')

        if self.security:
            raise NotImplementedError('Handling security data is not ' +
                                      'implemented yet')

        # "D" is the "DDT-originated" flag and is set by a DDT client to
        # indicate that the receiver can and should return Map-Referral
        # messages as appropriate.
        if not isinstance(self.ddt_originated, bool):
            raise ValueError('DDT originated flag must be a boolean')

        # LCM:   The format is one of the control message formats described in
        # this section.  At this time, only Map-Request messages are allowed
        # to be encapsulated.  And in the future, PIM Join-Prune messages
        # [MLISP] might be allowed.  Encapsulating other types of LISP
        # control messages are for further study.  When Map-Requests are
        # sent for RLOC-probing purposes (i.e the probe-bit is set), they
        # MUST NOT be sent inside Encapsulated Control Messages.

    def get_udp(self):
        # Encapsulated, look inside
        if not isinstance(self.payload, (IPv4Packet, IPv6Packet)):
            raise ValueError("Payload doesn't contain an IP header")

        # Don't try to interpret fragments
        if self.payload.is_fragmented():
            raise ValueError("Can't get UDP layer from a fragment")

        # Get to the upper layer protocol
        (proto_nr, udp) = self.payload.get_final_payload()
        if proto_nr != 17 or not isinstance(udp, UDPMessage):
            raise ValueError("IP payload is not UDP")

        return udp

    @classmethod
    def from_bytes(cls, bitstream):
        r'''
        Parse the given packet and update properties accordingly

        >>> data_hex = ('80000000'
        ...             '6e000000004811402a0086400001ffff'
        ...             '000000000000000a2a02000000000000'
        ...             '0000000000000000'
        ...             '10f610f600487396'
        ...             '10000201ee924adef97a97d700000001'
        ...             '57c3c44d00015f61535d0002200109e0'
        ...             '85000b000000000000000001000f0002'
        ...             '2a020000000000000000000000000000')
        >>> data = data_hex.decode('hex')
        >>> message = EncapsulatedControlMessage.from_bytes(data)
        >>> message.security
        False
        >>> message.ddt_originated
        False
        >>> bytes(message.payload)
        ... # doctest: +ELLIPSIS
        'n\x00\x00\x00\x00H\x11...\x00\x00'
        '''
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Read the type
        type_nr = bitstream.read('uint:4')
        if type_nr != packet.message_type:
            msg = 'Invalid bitstream for a {0} packet'
            class_name = packet.__class__.__name__
            raise ValueError(msg.format(class_name))

        # Read the flags
        (packet.security,
         packet.ddt_originated) = bitstream.readlist('2*bool')

        # Skip reserved bits
        bitstream.read(26)

        # If the security flag is set then there should be security data here
        # TODO: deal with security flag [LISP-Security]
        if packet.security:
            raise NotImplementedError('Handling security data is not ' +
                                      'implemented yet')

        # The rest of the packet is payload
        remaining = bitstream[bitstream.pos:]

        # Parse IP packet
        if len(remaining):
            ip_version = remaining.peek('uint:4')
            if ip_version == 4:
                packet.payload = IPv4Packet.from_bytes(remaining)
            elif ip_version == 6:
                packet.payload = IPv6Packet.from_bytes(remaining)
            else:
                packet.payload = remaining.bytes

        # Verify that the properties make sense
        packet.sanitize()

        return packet

    def to_bytes(self):
        r'''
        Create bytes from properties

        >>> message = EncapsulatedControlMessage(payload='Dummy')
        >>> message.to_bytes()
        '\x80\x00\x00\x00Dummy'
        '''
        # Verify that properties make sense
        self.sanitize()

        # Start with the type
        bitstream = BitArray('uint:4=%d' % self.message_type)

        # Add the flags
        bitstream += BitArray('bool=%d, bool=%d' % (self.security,
                                                    self.ddt_originated))

        # Add padding
        bitstream += BitArray(26)

        # Determine payload
        payload = self.payload
        if hasattr(payload, 'to_bytes'):
            payload = payload.to_bytes()

        return bitstream.bytes + payload


# Register this class in the registry
type_registry.register_type_class(EncapsulatedControlMessage)
