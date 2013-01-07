'''
Created on 5 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, BitArray
import collections
import numbers

__all__ = ['LISPDataPacket']


class LISPDataPacket(object):
    '''
    classdocs
    '''

    def __init__(self):
        '''
        Constructor
        '''
        # Initialise to default values
        self.nonce_present = False
        self.lsb_enabled = False
        self.echo_nonce_request = False
        self.map_version_present = False
        self.instance_id_present = False

        # We set nonce_present to False, so no nonce
        self.nonce = None

        # We set map_version_present to False, so no versions
        self.source_map_version = None
        self.destination_map_version = None

        # We set lsb_enabled to False, so no LSBs
        self.lsb = None

        # We set instance_id_present to False, so no instance id
        self.instance_id = None

        # No payload
        self.payload = ''

    def __repr__(self):
        return str(self.__dict__)

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
        if not isinstance(self.nonce_present, bool):
            raise ValueError('Nonce present flag must be a boolean')

        if self.nonce_present and self.map_version_present:
            # Fix conflict accorting to spec
            self.map_version_present = False

        if self.nonce_present:
            # Nonce must be a 24 bits (= 3 bytes) long bytestring
            if not isinstance(self.nonce, bytes) or len(self.nonce) != 3:
                raise ValueError('Invalid nonce')
        else:
            # Nonce must be empty
            self.nonce = None

        # The L bit is the Locator Status Bits field enabled bit.  When this
        # bit is set to 1, the Locator Status Bits in the second 32-bits of
        # the LISP header are in use.
        if not isinstance(self.lsb_enabled, bool):
            raise ValueError('LSB-enabled flag must be a boolean')

        if self.lsb_enabled:
            # Determine how many bits we expect
            if self.instance_id_present:
                lsb_bits = 8
            else:
                lsb_bits = 32

            # Check if LSBs is a sequence of booleans of the right length
            if not isinstance(self.lsb, collections.Sequence) \
            or len(self.lsb) != lsb_bits \
            or any(map(lambda v: type(v) != bool, self.lsb)):
                raise ValueError('Invalid locator status bits')
        else:
            self.lsb = None

        # The E bit is the echo-nonce-request bit.  This bit MUST be ignored
        # and has no meaning when the N bit is set to 0.  When the N bit is
        # set to 1 and this bit is set to 1, means an ITR is requesting for
        # the nonce value in the Nonce field to be echoed back in LISP
        # encapsulated packets when the ITR is also an ETR.  See
        # Section 6.3.1 for details.
        if not isinstance(self.echo_nonce_request, bool):
            raise ValueError('Echo-Nonce-Request flag must be a boolean')

        if self.echo_nonce_request and not self.nonce_present:
            self.echo_nonce_request = False

        # The V bit is the Map-Version present bit.  When this bit is set to
        # 1, the N bit MUST be 0.  Refer to Section 6.6.3 for more details.
        if not isinstance(self.map_version_present, bool):
            raise ValueError('Map-Version-Present flag must be a boolean')

        if self.map_version_present:
            if isinstance(self.source_map_version, numbers.Integral) \
            or self.source_map_version < 0 \
            or self.source_map_version >= 2 ** 12:
                raise ValueError('Invalid source map version')

            if isinstance(self.destination_map_version, numbers.Integral) \
            or self.destination_map_version < 0 \
            or self.destination_map_version >= 2 ** 12:
                raise ValueError('Invalid destination map version')
        else:
            self.source_map_version = None
            self.destination_map_version = None

        # The I bit is the Instance ID bit.  See Section 5.5 for more
        # details.  When this bit is set to 1, the Locator Status Bits field
        # is reduced to 8-bits and the high-order 24-bits are used as an
        # Instance ID.  If the L-bit is set to 0, then the low-order 8 bits
        # are transmitted as zero and ignored on receipt.
        if not isinstance(self.instance_id_present, bool):
            raise ValueError('Instance-ID-Present flag must be a boolean')

        if self.instance_id_present:
            if isinstance(self.instance_id, numbers.Integral) \
            or self.instance_id < 0 \
            or self.instance_id >= 2 ** 24:
                raise ValueError('Invalid instance id')
        else:
            self.instance_id = None

    @classmethod
    def from_bytes(cls, bitstream):
        '''
        Parse the given packet and update properties accordingly
        '''
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            bitstream = ConstBitStream(bytes=bitstream)

        # Read the flags
        (packet.nonce_present,
         packet.lsb_enabled,
         packet.echo_nonce_request,
         packet.map_version_present,
         packet.instance_id_present) = bitstream.readlist('5*bool')

        # Skip over reserved bits
        bitstream.read(3)

        # Parse nonce or map versions
        if packet.nonce_present:
            # Nonce: yes, versions: no
            packet.nonce = bitstream.read('bytes:3')
            packet.source_map_version = None
            packet.destination_map_version = None
        elif packet.map_version_present:
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
        if packet.instance_id_present:
            packet.instance_id = bitstream.read('uint:24')

            # 8 bits remaining for LSB
            lsb_bits = 8
        else:
            packet.instance_id = None

            # 32 bits remaining for LSB
            lsb_bits = 32

        # Parse LSBs
        if packet.lsb_enabled:
            packet.lsb = bitstream.readlist('%d*bool' % lsb_bits)

            # Reverse for readability: least significant locator-bit first
            packet.lsb.reverse()
        else:
            packet.lsb = None

            # Skip over the LSBs
            bitstream.read(lsb_bits)

        # The rest of the packet is payload
        remaining = bitstream[bitstream.pos:]
        packet.payload = remaining.bytes

        # Verify that the properties make sense
        packet.sanitize()

        return packet

    def to_bytes(self):
        '''
        Create bytes from properties
        '''
        # Verify that properties make sense
        self.sanitize()

        # Set the flags in the first 8 bits
        bitstream = BitArray('bool=%d, bool=%d, bool=%d, bool=%d, bool=%d'
                             % (self.nonce_present,
                                self.lsb_enabled,
                                self.echo_nonce_request,
                                self.map_version_present,
                                self.instance_id_present))

        # Add padding
        bitstream += BitArray(3)

        # Add the 24 bit nonce or the map-versions if present
        if self.nonce_present:
            # Nonce
            bitstream += BitArray(hex=self.nonce.encode('hex'))
        elif self.map_version_present:
            # Map versions
            bitstream += BitArray(('uint:12=%d, uint:12=%d')
                                  % (self.source_map_version,
                                     self.destination_map_version))
        else:
            # Padding
            bitstream += BitArray(24)

        # Add instance-id if present
        if self.instance_id_present:
            bitstream += BitArray('uint:24=%d' % self.instance_id)
            lsb_bits = 8
        else:
            lsb_bits = 32

        # Add LSBs if present
        if self.lsb_enabled:
            flags = map(lambda f: f and 'bool=1' or 'bool=0',
                        self.lsb[::-1])
            bitstream += BitArray(','.join(flags))
        else:
            bitstream += BitArray(lsb_bits)

        return bitstream.bytes + self.payload
