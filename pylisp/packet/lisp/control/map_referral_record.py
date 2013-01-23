'''
Created on 6 jan. 2013

@author: sander
'''
from IPy import IP
from bitstring import ConstBitStream, BitArray, Bits
from pylisp.packet.lisp.control import LocatorRecord
from pylisp.utils.afi import read_afi_address_from_bitstream, \
    get_bitstream_for_afi_address
import numbers


__all__ = ['MapReferralRecord']


class MapReferralRecord(object):
    # ACT: The "action" field of the mapping record in a Map-Referral
    # message encodes 6 action types.  The values for the action types are:
    #
    # NODE-REFERRAL (0):  Sent by a DDT node with a child delegation which
    #   is authoritative for the EID.
    #
    # MS-REFERRAL (1):  Sent by a DDT node that has information about Map
    #   Server(s) for the EID but it is not one of the Map Servers listed,
    #   i.e. the DDT-Node sending the referral is not a Map Server.
    #
    # MS-ACK (2):  Sent by a DDT Map Server that has one or more ETR
    #   registered for the EID.
    #
    # MS-NOT-REGISTERED (3):  Sent by a DDT Map Server that is configured
    #   for the EID-prefix but for which no ETRs are registered.
    #
    # DELEGATION-HOLE (4):  Sent by an intermediate DDT node with
    #   authoritative configuration covering the requested EID but without
    #   any child delegation for the EID.  Also sent by a DDT Map Server
    #   with authoritative configuration covering the requested EID but
    #   for which no specific site ETR is configured.
    #
    # NOT-AUTHORITATIVE (5):  Sent by a DDT node that does not have
    #   authoritative configuration for the requested EID.  The EID-prefix
    #   returned MUST be the original requested EID and the TTL MUST be
    #   set to 0.  However, if such a DDT node has a child delegation
    #   covering the requested EID, it may choose to return NODE-REFERRAL
    #   or MS-REFERRAL as appropriate.  A DDT Map Server with site
    #   information may choose to return of type MS-ACK or MS-NOT-
    #   REGISTERED as appropriate.
    #
    ACT_NODE_REFERRAL = 0
    ACT_MS_REFERRAL = 1
    ACT_MS_ACK = 2
    ACT_MS_NOT_REGISTERED = 3
    ACT_DELEGATION_HOLE = 4
    ACT_NOT_AUTHORITATIVE = 5

    def __init__(self, ttl=0, action=ACT_NODE_REFERRAL,
                 authoritative=False, incomplete=False, map_version=0,
                 eid_prefix=None, locator_records=None, signatures=None):
        '''
        Constructor
        '''
        # Set defaults
        self.ttl = ttl
        self.action = action
        self.authoritative = authoritative
        self.incomplete = incomplete
        self.map_version = map_version
        self.eid_prefix = eid_prefix
        self.locator_records = locator_records or []
        self.signatures = signatures or []

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
        # WARNING: http://tools.ietf.org/html/draft-ietf-lisp-ddt-00
        # does not define this field so the description is taken from
        # http://tools.ietf.org/html/draft-ietf-lisp-24
        #
        # Record TTL:  The time in minutes the recipient of the Map-Reply will
        # store the mapping.  If the TTL is 0, the entry SHOULD be removed
        # from the cache immediately.  If the value is 0xffffffff, the
        # recipient can decide locally how long to store the mapping.
        if not isinstance(self.ttl, numbers.Integral) \
        or self.ttl < 0 or self.ttl > 0xffffffff:
            raise ValueError('Invalid TTL')

        # ACT: The "action" field of the mapping record in a Map-Referral
        # message encodes 6 action types.  The values for the action types are:
        #
        # NODE-REFERRAL (0):  Sent by a DDT node with a child delegation which
        #   is authoritative for the EID.
        #
        # MS-REFERRAL (1):  Sent by a DDT node that has information about Map
        #   Server(s) for the EID but it is not one of the Map Servers listed,
        #   i.e. the DDT-Node sending the referral is not a Map Server.
        #
        # MS-ACK (2):  Sent by a DDT Map Server that has one or more ETR
        #   registered for the EID.
        #
        # MS-NOT-REGISTERED (3):  Sent by a DDT Map Server that is configured
        #   for the EID-prefix but for which no ETRs are registered.
        #
        # DELEGATION-HOLE (4):  Sent by an intermediate DDT node with
        #   authoritative configuration covering the requested EID but without
        #   any child delegation for the EID.  Also sent by a DDT Map Server
        #   with authoritative configuration covering the requested EID but
        #   for which no specific site ETR is configured.
        #
        # NOT-AUTHORITATIVE (5):  Sent by a DDT node that does not have
        #   authoritative configuration for the requested EID.  The EID-prefix
        #   returned MUST be the original requested EID and the TTL MUST be
        #   set to 0.  However, if such a DDT node has a child delegation
        #   covering the requested EID, it may choose to return NODE-REFERRAL
        #   or MS-REFERRAL as appropriate.  A DDT Map Server with site
        #   information may choose to return of type MS-ACK or MS-NOT-
        #   REGISTERED as appropriate.
        if self.action not in (self.ACT_NODE_REFERRAL,
                               self.ACT_MS_REFERRAL,
                               self.ACT_MS_ACK,
                               self.ACT_MS_NOT_REGISTERED,
                               self.ACT_DELEGATION_HOLE,
                               self.ACT_NOT_AUTHORITATIVE):
            raise ValueError('Invalid action')

        # WARNING: http://tools.ietf.org/html/draft-ietf-lisp-ddt-00
        # does not define this field so the description is taken from
        # http://tools.ietf.org/html/draft-ietf-lisp-24
        #
        # A: The Authoritative bit, when sent is always set to 1 by an ETR.
        # When a Map-Server is proxy Map-Replying [LISP-MS] for a LISP site,
        # the Authoritative bit is set to 0.  This indicates to requesting
        # ITRs that the Map-Reply was not originated by a LISP node managed
        # at the site that owns the EID-prefix.
        if not isinstance(self.authoritative, bool):
            raise ValueError('Authoritative flag must be a boolean')

        # Incomplete: The "I" bit indicates that a DDT node's referral-set of
        # locators is incomplete and the receiver of this message should not
        # cache the referral
        if not isinstance(self.incomplete, bool):
            raise ValueError('Incomplete flag must be a boolean')

        # A DDT sets the "incomplete" flag, the TTL, and the Action Type field
        # as follows:
        #
        # -------------------------------------------------------------------
        #  Type (Action field)          Incomplete Referral-set   TTL values
        # -------------------------------------------------------------------
        #   0    NODE-REFERRAL              NO         YES           1440
        #   1    MS-REFERRAL                NO         YES           1440
        #   2    MS-ACK                     *          *             1440
        #   3    MS-NOT-REGISTERED          *          *             1
        #   4    DELEGATION-HOLE            NO         NO            15
        #   5    NOT-AUTHORITATIVE          YES        NO            0
        # -------------------------------------------------------------------
        #
        # *: The "Incomplete" flag setting on Map Server originated referral of
        #   MS-REFERRAL and MS-NOT-REGISTERED types depend on whether the Map
        #   Server has the full peer Map Server configuration for the same
        #   prefix and has encoded the information in the mapping record.
        #   Incomplete bit is not set when the Map Server has encoded the
        #   information, which means the referral-set includes all the RLOCs
        #   of all Map Servers that serve the prefix.  It is set when the Map
        #   Server has not encoded the Map Server set information.
        if self.action == self.ACT_NODE_REFERRAL:
            if self.incomplete:
                raise ValueError('NODE-REFERRAL messages cannot be incomplete')

            if not self.locator_records:
                raise ValueError('NODE-REFERRAL messages must have locators')

            if self.ttl != 1440:
                raise ValueError('NODE-REFERRAL messages must have TTL=1440')

        elif self.action == self.ACT_MS_REFERRAL:
            if self.incomplete:
                raise ValueError('MS-REFERRAL messages cannot be incomplete')

            if not self.locator_records:
                raise ValueError('MS-REFERRAL messages must have locators')

            if self.ttl != 1440:
                raise ValueError('MS-REFERRAL messages must have TTL=1440')

        elif self.action == self.ACT_MS_ACK:
            if self.ttl != 1440:
                raise ValueError('MS-ACK messages must have TTL=1440')

        elif self.action == self.ACT_MS_NOT_REGISTERED:
            if self.ttl != 1:
                raise ValueError('MS-NOT-REGISTERED messages must have '
                                 'TTL=1')

        elif self.action == self.ACT_DELEGATION_HOLE:
            if self.incomplete:
                raise ValueError('DELEGATION-HOLE messages cannot be '
                                 'incomplete')

            if self.locator_records:
                raise ValueError('DELEGATION-HOLE messages can not have '
                                 'locators')

            if self.ttl != 15:
                raise ValueError('DELEGATION-HOLE messages must have TTL=15')

        elif self.action == self.ACT_NOT_AUTHORITATIVE:
            if not self.incomplete:
                raise ValueError('NOT-AUTHORITATIVE messages must be '
                                 'incomplete')

            if self.locator_records:
                raise ValueError('NOT-AUTHORITATIVE messages can not have '
                                 'locators')

            if self.ttl != 0:
                raise ValueError('NOT-AUTHORITATIVE messages must have TTL=0')

        # WARNING: http://tools.ietf.org/html/draft-ietf-lisp-ddt-00
        # does not define this field so the description is taken from
        # http://tools.ietf.org/html/draft-ietf-lisp-24
        #
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
# Disable until we have proper LCAF support
#        if not isinstance(self.eid_prefix, IP) \
#        or self.eid_prefix.version() not in (4, 6):
#            raise ValueError('EID prefix must be IPv4 or IPv6')

        # Check locator records
        # The local and probed_locator bits aren't used in this context
        for locator_record in self.locator_records:
            if not isinstance(locator_record, LocatorRecord) \
            or locator_record.local or locator_record.probed_locator:
                raise ValueError('Invalid Locator record')

            locator_record.sanitize()

        # Check signatures
        for dummy in self.signatures:
            # TODO: Implement signatures
            pass

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
        referral_count = bitstream.read('uint:8')

        # Store the EID prefix mask length until we need it
        eid_prefix_len = bitstream.read('uint:8')

        # Read the Negative Map_Reply action
        record.action = bitstream.read('uint:3')

        # Read the flags
        (record.authoritative,
         record.incomplete) = bitstream.readlist('2*bool')

        # Skip over reserved bits
        bitstream.read(11)

        # Read the signature count
        sig_count = bitstream.read('uint:4')

        # Read the map version
        record.map_version = bitstream.read('uint:12')

        # Read the EID prefix
        record.eid_prefix = read_afi_address_from_bitstream(bitstream,
                                                            eid_prefix_len)

        # Read the locator records
        for dummy in range(referral_count):
            locator_record = LocatorRecord.from_bytes(bitstream)
            record.locator_records.append(locator_record)

        # TODO: Can't handle signatures yet!
        if sig_count:
            raise NotImplementedError('Cannot handle signatures yet')

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
        bitstream += BitArray('bool=%d, bool=%d' % (self.authoritative,
                                                    self.incomplete))

        # Add reserved bits
        bitstream += BitArray(11)

        # Add sigcount
        bitstream += BitArray('uint:4=%d' % len(self.signatures))

        # Add the map version
        bitstream += BitArray('uint:12=%d' % self.map_version)

        # Add the EID prefix
        bitstream += get_bitstream_for_afi_address(self.eid_prefix)

        # Add the locator records
        for locator_record in self.locator_records:
            bitstream += locator_record.to_bitstream()

        # TODO: Can't handle signatures yet!
        if self.signatures:
            raise NotImplementedError('Cannot handle signatures yet')

        return bitstream
