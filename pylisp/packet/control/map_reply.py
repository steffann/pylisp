'''
Created on 6 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, BitArray
from pylisp.packet.control import type_registry
from pylisp.packet.control.base import LISPControlMessage
from pylisp.packet.control.map_reply_record import LISPMapReplyRecord


__all__ = ['LISPMapReplyMessage']


class LISPMapReplyMessage(LISPControlMessage):
    # Class property: which message type do we represent?
    message_type = 2

    def __init__(self, probe=False, enlra_enabled=False, security=False,
                 nonce='\x00\x00\x00\x00\x00\x00\x00\x00', records=None):
        '''
        Constructor
        '''
        super(LISPMapReplyMessage, self).__init__()

        # Set defaults
        self.probe = probe
        self.enlra_enabled = enlra_enabled
        self.security = security
        self.nonce = nonce
        self.records = records or []

    def __repr__(self):
        return str(self.__dict__)

    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix them where possible.
        '''
        super(LISPMapReplyMessage, self).sanitize()

        # P: This is the probe-bit which indicates that the Map-Reply is in
        # response to a locator reachability probe Map-Request.  The nonce
        # field MUST contain a copy of the nonce value from the original
        # Map-Request.  See Section 6.3.2 for more details.
        if not isinstance(self.probe, bool):
            raise ValueError('Probe flag must be a boolean')

        # E: Indicates that the ETR which sends this Map-Reply message is
        # advertising that the site is enabled for the Echo-Nonce locator
        # reachability algorithm.  See Section 6.3.1 for more details.
        if not isinstance(self.enlra_enabled, bool):
            raise ValueError('Echo-Nonce Locator Reachability algorithm ' +
                             'enabled flag must be a boolean')

        # S: This is the Security bit.  When set to 1 the following
        # authentication information will be appended to the end of the Map-
        # Reply.  The detailed format of the Authentication Data Content is
        # for further study.
        if not isinstance(self.security, bool):
            raise ValueError('Security flag must be a boolean')

        if self.security:
            raise NotImplementedError('Handling security data is not ' +
                                      'implemented yet')

        # Nonce:  A 24-bit value set in a Data-Probe packet or a 64-bit value
        # from the Map-Request is echoed in this Nonce field of the Map-
        # Reply.  When a 24-bit value is supplied, it resides in the low-
        # order 64 bits of the nonce field.
        if not isinstance(self.nonce, bytes) or len(self.nonce) not in (3, 8):
            raise ValueError('Invalid nonce')

        # Map-Reply Record:  When the M bit is set, this field is the size of a
        # single "Record" in the Map-Reply format.  This Map-Reply record
        # contains the EID-to-RLOC mapping entry associated with the Source
        # EID.  This allows the ETR which will receive this Map-Request to
        # cache the data if it chooses to do so.
        for record in self.records:
            if not isinstance(record, LISPMapReplyRecord):
                raise ValueError('Invalid record')

            record.sanitize()

    @classmethod
    def from_bytes(cls, bitstream):
        '''
        Parse the given packet and update properties accordingly
        '''
        packet = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            bitstream = ConstBitStream(bytes=bitstream)

        # Read the type
        type_nr = bitstream.read('uint:4')
        if type_nr != packet.message_type:
            msg = 'Invalid bitstream for a {0} packet'
            class_name = packet.__class__.__name__
            raise ValueError(msg.format(class_name))

        # Read the flags
        (packet.probe,
         packet.enlra_enabled,
         packet.security) = bitstream.readlist('3*bool')

        # Skip reserved bits
        bitstream.read(17)

        # Store the record count until we need it
        record_count = bitstream.read('uint:8')

        # Read the nonce
        packet.nonce = bitstream.read('bytes:8')

        # Read the records
        for dummy in range(record_count):
            record = LISPMapReplyRecord.from_bytes(bitstream)
            packet.records.append(record)

        # If the security flag is set then there should be security data left
        # TODO: deal with it
        if packet.security:
            raise NotImplementedError('Handling security data is not ' +
                                      'implemented yet')

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
        # Verify that properties make sense
        self.sanitize()

        # Start with the type
        bitstream = BitArray('uint:4=%d' % self.message_type)

        # Add the flags
        bitstream += BitArray('bool=%d, bool=%d, bool=%d'
                              % (self.probe,
                                 self.enlra_enabled,
                                 self.security))

        # Add padding
        bitstream += BitArray(17)

        # Add record count
        bitstream += BitArray('uint:8=%d' % len(self.records))

        # Add the nonce
        if len(self.nonce) < 8:
            padding_len = 8 - len(self.nonce)
            bitstream += BitArray(8 * padding_len)
            
        bitstream += BitArray(hex=self.nonce.encode('hex'))

        # Add the map-reply records
        for record in self.records:
            bitstream += record.to_bitstream()

        # If the security flag is set then there should be security data here
        # TODO: deal with it
        if self.security:
            raise NotImplementedError('Handling security data is not ' +
                                      'implemented yet')

        return bitstream.bytes


# Register this class in the registry
type_registry.register_type_class(LISPMapReplyMessage)
