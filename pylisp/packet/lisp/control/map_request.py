'''
Created on 6 jan. 2013

@author: sander
'''
from IPy import IP
from bitstring import ConstBitStream, BitArray, Bits
from pylisp.packet.lisp.control import type_registry, LISPControlMessage, \
    LISPMapReplyRecord
from pylisp.utils.afi import read_afi_address_from_bitstream, \
    get_bitstream_for_afi_address


__all__ = ['LISPMapRequestMessage']


class LISPMapRequestMessage(LISPControlMessage):
    # Class property: which message type do we represent?
    message_type = 1

    def __init__(self, authoritative=False, probe=False, smr=False, pitr=False,
                 smr_invoked=False, nonce='\x00\x00\x00\x00\x00\x00\x00\x00',
                 source_eid=None, itr_rlocs=None, eid_prefixes=None,
                 map_reply=None):
        '''
        Constructor
        '''
        super(LISPMapRequestMessage, self).__init__()

        # Set defaults
        self.authoritative = authoritative
        self.probe = probe
        self.smr = smr
        self.pitr = pitr
        self.smr_invoked = smr_invoked
        self.nonce = nonce
        self.source_eid = source_eid
        self.itr_rlocs = itr_rlocs or []
        self.eid_prefixes = eid_prefixes or []
        self.map_reply = map_reply

    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix them where possible.
        '''
        super(LISPMapRequestMessage, self).sanitize()

        # A: This is an authoritative bit, which is set to 0 for UDP-based Map-
        # Requests sent by an ITR.  Set to 1 when an ITR wants the
        # destination site to return the Map-Reply rather than the mapping
        # database system.
        if not isinstance(self.authoritative, bool):
            raise ValueError('Authoritative flag must be a boolean')

        # M: This is the map-data-present bit, when set, it indicates a Map-
        # Reply Record segment is included in the Map-Request.
        # Checked below

        # P: This is the probe-bit which indicates that a Map-Request SHOULD be
        # treated as a locator reachability probe.  The receiver SHOULD
        # respond with a Map-Reply with the probe-bit set, indicating the
        # Map-Reply is a locator reachability probe reply, with the nonce
        # copied from the Map-Request.  See Section 6.3.2 for more details.
        if not isinstance(self.probe, bool):
            raise ValueError('Probe flag must be a boolean')

        # S: This is the Solicit-Map-Request (SMR) bit.  See Section 6.6.2 for
        # details.
        if not isinstance(self.smr, bool):
            raise ValueError('SMR flag must be a boolean')

        # p: This is the PITR bit.  This bit is set to 1 when a PITR sends a
        # Map-Request.
        if not isinstance(self.pitr, bool):
            raise ValueError('PITR flag must be a boolean')

        # s: This is the SMR-invoked bit.  This bit is set to 1 when an xTR is
        # sending a Map-Request in response to a received SMR-based Map-
        # Request.
        if not isinstance(self.smr_invoked, bool):
            raise ValueError('SMR-invoked flag must be a boolean')

        # IRC:  This 5-bit field is the ITR-RLOC Count which encodes the
        # additional number of (ITR-RLOC-AFI, ITR-RLOC Address) fields
        # present in this message.  At least one (ITR-RLOC-AFI, ITR-RLOC-
        # Address) pair MUST be encoded.  Multiple ITR-RLOC Address fields
        # are used so a Map-Replier can select which destination address to
        # use for a Map-Reply.  The IRC value ranges from 0 to 31.  For a
        # value of 0, there is 1 ITR-RLOC address encoded, and for a value
        # of 1, there are 2 ITR-RLOC addresses encoded and so on up to 31
        # which encodes a total of 32 ITR-RLOC addresses.
        if len(self.itr_rlocs) < 1 or len(self.itr_rlocs) > 32:
            raise ValueError('Number of ITR RLOCs must be between 1 and 32')

        # Record Count:  The number of records in this Map-Request message.  A
        # record is comprised of the portion of the packet that is labeled
        # 'Rec' above and occurs the number of times equal to Record Count.
        # For this version of the protocol, a receiver MUST accept and
        # process Map-Requests that contain one or more records, but a
        # sender MUST only send Map-Requests containing one record.  Support
        # for requesting multiple EIDs in a single Map-Request message will
        # be specified in a future version of the protocol.
        if len(self.eid_prefixes) < 1 or len(self.eid_prefixes) > 32:
            raise ValueError('Number of EID prefix records must be between ' +
                             '1 and 255')

        # Nonce: An 8-octet random value created by the sender of the Map-
        # Request.  This nonce will be returned in the Map-Reply.  The
        # security of the LISP mapping protocol depends critically on the
        # strength of the nonce in the Map-Request message.  The nonce
        # SHOULD be generated by a properly seeded pseudo-random (or strong
        # random) source.  See [RFC4086] for advice on generating security-
        # sensitive random data.
        if len(bytes(self.nonce)) != 8:
            raise ValueError('Invalid nonce')

        # Source EID Address:  This is the EID of the source host which
        # originated the packet which is caused the Map-Request.  When Map-
        # Requests are used for refreshing a map-cache entry or for RLOC-
        # probing, an AFI value 0 is used and this field is of zero length.
        if self.source_eid is not None:
#            if not isinstance(self.source_eid, IP) \
#            or self.source_eid.len() != 1:
#                raise ValueError('Invalid source EID: %r' % self.source_eid)
            if self.source_eid.len() != 1:
                raise ValueError('Invalid source EID')

        # ITR-RLOC Address:  Used to give the ETR the option of selecting the
        # destination address from any address family for the Map-Reply
        # message.  This address MUST be a routable RLOC address of the
        # sender of the Map-Request message.
        for itr_rloc in self.itr_rlocs:
            if not isinstance(itr_rloc, IP) \
            or itr_rloc.len() != 1:
                raise ValueError('Invalid ITR RLOC')

        # EID-prefix:  4 octets if an IPv4 address-family, 16 octets if an IPv6
        # address-family.  When a Map-Request is sent by an ITR because a
        # data packet is received for a destination where there is no
        # mapping entry, the EID-prefix is set to the destination IP address
        # of the data packet.  And the 'EID mask-len' is set to 32 or 128
        # for IPv4 or IPv6, respectively.  When an xTR wants to query a site
        # about the status of a mapping it already has cached, the EID-
        # prefix used in the Map-Request has the same mask-length as the
        # EID-prefix returned from the site when it sent a Map-Reply
        # message.
#        for eid_prefix in self.eid_prefixes:
#            if not isinstance(eid_prefix, IP):
#                raise ValueError('Invalid EID prefix')

        # Map-Reply Record:  When the M bit is set, this field is the size of a
        # single "Record" in the Map-Reply format.  This Map-Reply record
        # contains the EID-to-RLOC mapping entry associated with the Source
        # EID.  This allows the ETR which will receive this Map-Request to
        # cache the data if it chooses to do so.
        if self.map_reply is not None:
            if not isinstance(self.map_reply, LISPMapReplyRecord):
                raise ValueError('Invalid Map-Reply')

            self.map_reply.sanitize()

    @classmethod
    def from_bytes(cls, bitstream):
        r'''
        Parse the given packet and update properties accordingly

        >>> data_hex = ('13000001ae92b5574f849cd00001ac10'
        ...             '1f0300015cfe1cbd00200001ac101f01')
        >>> data = data_hex.decode('hex')
        >>> message = LISPControlMessage.from_bytes(data)
        >>> message.message_type
        1
        >>> message.authoritative
        False
        >>> message.probe
        True
        >>> message.smr
        True
        >>> message.pitr
        False
        >>> message.smr_invoked
        False
        >>> message.nonce
        '\xae\x92\xb5WO\x84\x9c\xd0'
        >>> message.source_eid
        IP('172.16.31.3')
        >>> message.itr_rlocs
        [IP('92.254.28.189')]
        >>> message.eid_prefixes
        [IP('172.16.31.1')]
        >>> message.map_reply
        '''
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Read the message type
        type_nr = bitstream.read('uint:4')
        if type_nr != packet.message_type:
            msg = 'Invalid bitstream for a {0} packet'
            class_name = packet.__class__.__name__
            raise ValueError(msg.format(class_name))

        # Read the flags
        (packet.authoritative,
         map_data_present,
         packet.probe,
         packet.smr,
         packet.pitr,
         packet.smr_invoked) = bitstream.readlist('6*bool')

        # Skip over reserved bits
        bitstream.read(9)

        # Save the IRC until we reach the actual data
        irc = bitstream.read('uint:5')

        # Save the record count until we reach the actual data
        record_count = bitstream.read('uint:8')

        # Read the nonce
        packet.nonce = bitstream.read('bytes:8')

        # Read the source EID
        packet.source_eid = read_afi_address_from_bitstream(bitstream)

        # Read the ITR RLOCs
        for dummy in range(irc + 1):
            itr_rloc = read_afi_address_from_bitstream(bitstream)
            packet.itr_rlocs.append(itr_rloc)

        # Read the EIDs
        for dummy in range(record_count):
            # A records begins with 8 reserved bits: skip
            bitstream.read(8)

            # Read 8 bits for the prefix length
            prefix_len = bitstream.read('uint:8')

            # Then an AFI style prefix
            eid_prefix = read_afi_address_from_bitstream(bitstream, prefix_len)
            packet.eid_prefixes.append(eid_prefix)

        # Read the map-reply record if present
        if map_data_present:
            packet.map_reply = LISPMapReplyRecord.from_bytes(bitstream)

        # There should be no remaining bits
        if bitstream.pos != bitstream.len:
            raise ValueError('Bits remaining after processing packet')

        # Verify that the properties make sense
        packet.sanitize()

        return packet

    def to_bytes(self):
        r'''
        Create bytes from properties

        >>> message = LISPMapRequestMessage(itr_rlocs=[IP('192.0.2.1')],
        ...                                 eid_prefixes=[IP('2001:db8::/32')])
        >>> hex = message.to_bytes().encode('hex')
        >>> hex[:40]
        '10000001000000000000000000000001c0000201'
        >>> hex[40:]
        '0020000220010db8000000000000000000000000'
        '''
        # Verify that properties make sense
        self.sanitize()

        # Start with the type
        bitstream = BitArray('uint:4=%d' % self.message_type)

        # Add the flags
        bitstream += BitArray('bool=%d, bool=%d, bool=%d, bool=%d, '
                              'bool=%d, bool=%d' % (self.authoritative,
                                                    self.map_reply is not None,
                                                    self.probe,
                                                    self.smr,
                                                    self.pitr,
                                                    self.smr_invoked))

        # Add padding
        bitstream += BitArray(9)

        # Add IRC
        bitstream += BitArray('uint:5=%d' % (len(self.itr_rlocs) - 1))

        # Add record count
        bitstream += BitArray('uint:8=%d' % len(self.eid_prefixes))

        # Add the nonce
        bitstream += BitArray(bytes=self.nonce)

        # Add the source EID
        bitstream += get_bitstream_for_afi_address(self.source_eid)

        # Add the ITR RLOCs
        for itr_rloc in self.itr_rlocs:
            bitstream += get_bitstream_for_afi_address(itr_rloc)

        # Add the EIDs
        for eid_prefix in self.eid_prefixes:
            # Add padding and prefix length
            bitstream += BitArray('uint:8=0, '
                                  'uint:8=%d' % eid_prefix.prefixlen())

            # Add the address
            bitstream += get_bitstream_for_afi_address(eid_prefix)

        # Add the map-reply record if present
        if self.map_reply is not None:
            bitstream += self.map_reply.to_bitstream()

        return bitstream.bytes


# Register this class in the registry
type_registry.register_type_class(LISPMapRequestMessage)
