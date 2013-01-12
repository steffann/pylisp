'''
Created on 6 jan. 2013

@author: sander
'''
from IPy import IP
from bitstring import ConstBitStream, BitArray, Bits
from pylisp.packet.lisp.control import LISPLocatorRecord
from pylisp.utils.afi import read_afi_address_from_bitstream, \
    get_bitstream_for_afi_address
import numbers


__all__ = ['LISPMapReplyRecord']


class LISPMapReplyRecord(object):
    # The actions defined are used by an ITR or PITR when a
    # destination EID matches a negative mapping cache entry.
    # Unassigned values should cause a map-cache entry to be created
    # and, when packets match this negative cache entry, they will be
    # dropped.  The current assigned values are:
    #
    # (0) No-Action:  The map-cache is kept alive and no packet
    #    encapsulation occurs.
    #
    # (1) Natively-Forward:  The packet is not encapsulated or dropped
    #    but natively forwarded.
    #
    # (2) Send-Map-Request:  The packet invokes sending a Map-Request.
    #
    # (3) Drop:  A packet that matches this map-cache entry is dropped.
    #    An ICMP Unreachable message SHOULD be sent.
    ACT_NO_ACTION = 0
    ACT_NATIVELY_FORWARD = 1
    ACT_SEND_MAP_REQUEST = 2
    ACT_DROP = 3

    def __init__(self, ttl=0, action=ACT_NO_ACTION, authoritative=False,
                 map_version=0, eid_prefix=None, locator_records=None):
        '''
        Constructor
        '''
        # Set defaults
        self.ttl = ttl
        self.action = action
        self.authoritative = authoritative
        self.map_version = map_version
        self.eid_prefix = eid_prefix
        self.locator_records = locator_records or []

    def __repr__(self):
        # This works as long as we accept all properties as paramters in the
        # constructor
        params = ['%s=%r' % (k, v) for k, v in self.__dict__.iteritems()]
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(params))

    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix where possible.
        '''
        # Record TTL:  The time in minutes the recipient of the Map-Reply will
        # store the mapping.  If the TTL is 0, the entry SHOULD be removed
        # from the cache immediately.  If the value is 0xffffffff, the
        # recipient can decide locally how long to store the mapping.
        if not isinstance(self.ttl, numbers.Integral) \
        or self.ttl < 0 or self.ttl > 0xffffffff:
            raise ValueError('Invalid TTL')

        # ACT:  This 3-bit field describes negative Map-Reply actions.  In any
        # other message type, these bits are set to 0 and ignored on
        # receipt.  These bits are used only when the 'Locator Count' field
        # is set to 0.  The action bits are encoded only in Map-Reply
        # messages.  The actions defined are used by an ITR or PITR when a
        # destination EID matches a negative mapping cache entry.
        # Unassigned values should cause a map-cache entry to be created
        # and, when packets match this negative cache entry, they will be
        # dropped.  The current assigned values are:
        #
        #  (0) No-Action:  The map-cache is kept alive and no packet
        #     encapsulation occurs.
        #
        #  (1) Natively-Forward:  The packet is not encapsulated or dropped
        #     but natively forwarded.
        #
        #  (2) Send-Map-Request:  The packet invokes sending a Map-Request.
        #
        #  (3) Drop:  A packet that matches this map-cache entry is dropped.
        #     An ICMP Unreachable message SHOULD be sent.
        if self.locator_records:
            self.action = self.ACT_NO_ACTION

        if self.action not in (self.ACT_NO_ACTION,
                               self.ACT_NATIVELY_FORWARD,
                               self.ACT_SEND_MAP_REQUEST,
                               self.ACT_DROP):
            raise ValueError('Invalid Negative Map-Reply action')

        # A: The Authoritative bit, when sent is always set to 1 by an ETR.
        # When a Map-Server is proxy Map-Replying [LISP-MS] for a LISP site,
        # the Authoritative bit is set to 0.  This indicates to requesting
        # ITRs that the Map-Reply was not originated by a LISP node managed
        # at the site that owns the EID-prefix.
        if not isinstance(self.authoritative, bool):
            raise ValueError('Authoritative flag must be a boolean')

        # Map-Version Number:  When this 12-bit value is non-zero the Map-Reply
        # sender is informing the ITR what the version number is for the
        # EID-record contained in the Map-Reply.  The ETR can allocate this
        # number internally but MUST coordinate this value with other ETRs
        # for the site.  When this value is 0, there is no versioning
        # information conveyed.  The Map-Version Number can be included in
        # Map-Request and Map-Register messages.  See Section 6.6.3 for more
        # details.
        if not isinstance(self.map_version, numbers.Integral) \
        or self.map_version < 0 \
        or self.map_version >= 2 ** 12:
            raise ValueError('Invalid map version')

        # EID-prefix:  4 octets if an IPv4 address-family, 16 octets if an IPv6
        # address-family.
        if not isinstance(self.eid_prefix, IP) \
        or self.eid_prefix.version() not in (4, 6):
            raise ValueError('EID prefix must be IPv4 or IPv6')

        # Check locator records
        for locator_record in self.locator_records:
            if not isinstance(locator_record, LISPLocatorRecord):
                raise ValueError('Invalid Locator record')

            locator_record.sanitize()

    @classmethod
    def from_bytes(cls, bitstream):
        '''
        Parse the given record and update properties accordingly
        '''
        record = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Read the record TTL
        record.ttl = bitstream.read('uint:32')

        # Store the locator record count until we need it
        locator_record_count = bitstream.read('uint:8')

        # Store the EID prefix mask length until we need it
        eid_prefix_len = bitstream.read('uint:8')

        # Read the Negative Map_Reply action
        record.action = bitstream.read('uint:3')

        # Read the flag
        record.authoritative = bitstream.read('bool')

        # Skip over reserved bits
        bitstream.read(12 + 4)

        # Read the map version
        record.map_version = bitstream.read('uint:12')

        # Read the EID prefix
        record.eid_prefix = read_afi_address_from_bitstream(bitstream,
                                                            eid_prefix_len)

        # Read the locator records
        for dummy in range(locator_record_count):
            locator_record = LISPLocatorRecord.from_bytes(bitstream)
            record.locator_records.append(locator_record)

        # Verify that the properties make sense
        record.sanitize()

        return record

    def to_bytes(self):
        '''
        Create bytes from properties
        '''
        return self.to_bitstream().bytes

    def to_bitstream(self):
        '''
        Create bitstream from properties
        '''
        # Verify that properties make sense
        self.sanitize()

        # Start with the TTL
        bitstream = BitArray('uint:32=%d' % self.ttl)

        # Add the locator count
        bitstream += BitArray('uint:8=%d' % len(self.locator_records))

        # Add the EID prefix mask length
        bitstream += BitArray('uint:8=%d' % self.eid_prefix.prefixlen())

        # Add the NMR action
        bitstream += BitArray('uint:3=%d' % self.action)

        # Add the authoritative flag
        bitstream += BitArray('bool=%d' % self.authoritative)

        # Add reserved bits
        bitstream += BitArray(12 + 4)

        # Add the map version
        bitstream += BitArray('uint:12=%d' % self.map_version)

        # Add the EID prefix
        bitstream += get_bitstream_for_afi_address(self.eid_prefix)

        # Add the locator records
        for locator_record in self.locator_records:
            bitstream += locator_record.to_bitstream()

        return bitstream
