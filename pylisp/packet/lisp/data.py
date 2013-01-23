'''
Created on 5 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, BitArray, Bits
from pylisp.packet.ip.ipv4 import IPv4Packet
from pylisp.packet.ip.ipv6.base import IPv6Packet
from pylisp.packet.ip.protocol import Protocol
import collections
import numbers

__all__ = ['DataPacket']


class DataPacket(Protocol):
    '''
    classdocs
    '''

    def __init__(self, echo_nonce_request=False, nonce=None,
                 source_map_version=None, destination_map_version=None,
                 lsb=None, instance_id=None, payload=''):
        '''
        Constructor
        '''
        # Initialise
        self.echo_nonce_request = echo_nonce_request
        self.nonce = nonce
        self.source_map_version = source_map_version
        self.destination_map_version = destination_map_version
        self.lsb = lsb
        self.instance_id = instance_id
        self.payload = payload

    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix where possible.
        '''
        # The N bit is the nonce-present bit.  When this bit is set to 1,
        # the low-order 24-bits of the first 32-bits of the LISP header
        # contains a Nonce.  See Section 6.3.1 for details.  Both N and V
        # bits MUST NOT be set in the same packet.  If they are, a
        # decapsulating ETR MUST treat the "Nonce/Map-Version" field as
        # having a Nonce value present.
        if self.nonce is not None and (not isinstance(self.nonce, bytes) or
                                       len(self.nonce) != 3):
            raise ValueError('Nonce must be a None or a sequence of 3 bytes')

        if self.nonce is not None \
        and (self.source_map_version is not None or
             self.destination_map_version is not None):
            raise ValueError('Cannot have both a nonce and map versions')

        # The L bit is the Locator Status Bits field enabled bit.  When this
        # bit is set to 1, the Locator Status Bits in the second 32-bits of
        # the LISP header are in use.
        if self.lsb is not None:
            # Determine how many bits we expect
            if self.instance_id is not None:
                lsb_bits = 8
            else:
                lsb_bits = 32

            # Check if LSBs is a sequence of booleans of the right length
            if not isinstance(self.lsb, collections.Sequence) \
            or len(self.lsb) != lsb_bits \
            or any(map(lambda v: type(v) != bool, self.lsb)):
                raise ValueError('Invalid locator status bits')

        # The E bit is the echo-nonce-request bit.  This bit MUST be ignored
        # and has no meaning when the N bit is set to 0.  When the N bit is
        # set to 1 and this bit is set to 1, means an ITR is requesting for
        # the nonce value in the Nonce field to be echoed back in LISP
        # encapsulated packets when the ITR is also an ETR.  See
        # Section 6.3.1 for details.
        if not isinstance(self.echo_nonce_request, bool):
            raise ValueError('Echo-Nonce-Request flag must be a boolean')

        if self.echo_nonce_request and self.nonce is None:
            self.echo_nonce_request = False

        # The V bit is the Map-Version present bit.  When this bit is set to
        # 1, the N bit MUST be 0.  Refer to Section 6.6.3 for more details.
        if self.source_map_version is not None \
        or self.destination_map_version is not None:
            if not isinstance(self.source_map_version, numbers.Integral) \
            or self.source_map_version < 0 \
            or self.source_map_version >= 2 ** 12:
                raise ValueError('Invalid source map version')

            if not isinstance(self.destination_map_version, numbers.Integral) \
            or self.destination_map_version < 0 \
            or self.destination_map_version >= 2 ** 12:
                raise ValueError('Invalid destination map version')

        # The I bit is the Instance ID bit.  See Section 5.5 for more
        # details.  When this bit is set to 1, the Locator Status Bits field
        # is reduced to 8-bits and the high-order 24-bits are used as an
        # Instance ID.  If the L-bit is set to 0, then the low-order 8 bits
        # are transmitted as zero and ignored on receipt.
        if self.instance_id is not None:
            if not isinstance(self.instance_id, numbers.Integral) \
            or self.instance_id < 0 \
            or self.instance_id >= 2 ** 24:
                raise ValueError('Invalid instance id')

    @classmethod
    def from_bytes(cls, bitstream):
        r'''
        Parse the given packet and update properties accordingly

        >>> data_hex = ('c033d3c10000000745c0005835400000'
        ...             'ff06094a254d38204d45d1a30016f597'
        ...             'a1c3c7406718bf1b50180ff0793f0000'
        ...             'b555e59ff5ba6aad33d875c600fd8c1f'
        ...             'c5268078f365ee199179fbd09d09d690'
        ...             '193622a6b70bcbc7bf5f20dda4258801')
        >>> data = data_hex.decode('hex')
        >>> message = DataPacket.from_bytes(data)
        >>> message.echo_nonce_request
        False
        >>> message.nonce
        '3\xd3\xc1'
        >>> message.source_map_version
        >>> message.destination_map_version
        >>> message.lsb
        ... # doctest: +ELLIPSIS
        [True, True, True, False, False, ..., False, False, False, False]
        >>> message.instance_id
        >>> bytes(message.payload)
        ... # doctest: +ELLIPSIS
        'E\xc0\x00X5@\x00\x00\xff\x06\tJ%M8...\xdd\xa4%\x88\x01'
        '''
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Read the flags
        (nonce_present,
         lsb_enabled,
         packet.echo_nonce_request,
         map_version_present,
         instance_id_present) = bitstream.readlist('5*bool')

        # Skip over reserved bits
        bitstream.read(3)

        # Parse nonce or map versions
        if nonce_present:
            # Nonce: yes, versions: no
            packet.nonce = bitstream.read('bytes:3')
            packet.source_map_version = None
            packet.destination_map_version = None
        elif map_version_present:
            # Nonce: no, versions: yes
            packet.nonce = None
            (packet.source_map_version,
             packet.destination_map_version) = bitstream.readlist('2*uint:12')
        else:
            # Nonce: no, versions: no
            packet.nonce = None
            packet.source_map_version = None
            packet.destination_map_version = None

            # Skip over the nonce/map-version bits
            bitstream.read(24)

        # Parse instance-id
        if instance_id_present:
            packet.instance_id = bitstream.read('uint:24')

            # 8 bits remaining for LSB
            lsb_bits = 8
        else:
            # 32 bits remaining for LSB
            lsb_bits = 32

        # Parse LSBs
        if lsb_enabled:
            packet.lsb = bitstream.readlist('%d*bool' % lsb_bits)

            # Reverse for readability: least significant locator-bit first
            packet.lsb.reverse()
        else:
            # Skip over the LSBs
            bitstream.read(lsb_bits)

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

        >>> message = DataPacket(nonce='XyZ', instance_id=1234,
        ...                      payload='SomeDummyPayloadData')
        >>> message.to_bytes()
        '\x88XyZ\x00\x04\xd2\x00SomeDummyPayloadData'
        '''
        # Verify that properties make sense
        self.sanitize()

        # Set the flags in the first 8 bits
        bitstream = BitArray('bool=%d, bool=%d, bool=%d, bool=%d, bool=%d'
                             % (self.nonce is not None,
                                self.lsb is not None,
                                self.echo_nonce_request,
                                (self.source_map_version is not None or
                                 self.destination_map_version is not None),
                                self.instance_id is not None))

        # Add padding
        bitstream += BitArray(3)

        # Add the 24 bit nonce or the map-versions if present
        if self.nonce is not None:
            # Nonce
            bitstream += BitArray(bytes=self.nonce)
        elif self.source_map_version is not None \
        or self.destination_map_version is not None:
            # Map versions
            bitstream += BitArray(('uint:12=%d, uint:12=%d')
                                  % (self.source_map_version,
                                     self.destination_map_version))
        else:
            # Padding
            bitstream += BitArray(24)

        # Add instance-id if present
        if self.instance_id is not None:
            bitstream += BitArray('uint:24=%d' % self.instance_id)
            lsb_bits = 8
        else:
            lsb_bits = 32

        # Add LSBs if present
        if self.lsb is not None:
            flags = map(lambda f: f and 'bool=1' or 'bool=0',
                        self.lsb[::-1])
            bitstream += BitArray(','.join(flags))
        else:
            bitstream += BitArray(lsb_bits)

        return bitstream.bytes + bytes(self.payload)
