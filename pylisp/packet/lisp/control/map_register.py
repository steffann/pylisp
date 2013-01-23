'''
Created on 6 jan. 2013

@author: sander
'''
from base import ControlMessage
from bitstring import ConstBitStream, BitArray, Bits
from pylisp.packet.lisp.control import type_registry, KEY_ID_HMAC_SHA_1_96, \
    KEY_ID_HMAC_SHA_256_128, KEY_ID_NONE, MapReplyRecord
import hashlib
import hmac


__all__ = ['MapRegisterMessage']


class MapRegisterMessage(ControlMessage):
    # Class property: which message type do we represent?
    message_type = 3

    def __init__(self, proxy_map_reply=False, want_map_notify=False,
                 nonce='\x00\x00\x00\x00\x00\x00\x00\x00', key_id=0,
                 authentication_data='', records=None):
        '''
        Constructor
        '''
        super(MapRegisterMessage, self).__init__()

        # Set defaults
        self.proxy_map_reply = proxy_map_reply
        self.want_map_notify = want_map_notify
        self.nonce = nonce
        self.key_id = key_id
        self.authentication_data = authentication_data
        self.records = records or []

    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix them where possible.
        '''
        super(MapRegisterMessage, self).sanitize()

        # P: This is the proxy-map-reply bit, when set to 1 an ETR sends a Map-
        # Register message requesting for the Map-Server to proxy Map-Reply.
        # The Map-Server will send non-authoritative Map-Replies on behalf
        # of the ETR.  Details on this usage can be found in [LISP-MS].
        if not isinstance(self.proxy_map_reply, bool):
            raise ValueError('Proxy Map Reply flag must be a boolean')

        # M: This is the want-map-notify bit, when set to 1 an ETR is
        # requesting for a Map-Notify message to be returned in response to
        # sending a Map-Register message.  The Map-Notify message sent by a
        # Map-Server is used to an acknowledge receipt of a Map-Register
        # message.
        if not isinstance(self.want_map_notify, bool):
            raise ValueError('Want Map Notify flag must be a boolean')

        # Nonce:  This 8-octet Nonce field is set to 0 in Map-Register
        # messages.  Since the Map-Register message is authenticated, the
        # nonce field is not currently used for any security function but
        # may be in the future as part of an anti-replay solution.
        if len(bytes(self.nonce)) != 8:
            raise ValueError('Invalid nonce')

        # Key ID:  A configured ID to find the configured Message
        # Authentication Code (MAC) algorithm and key value used for the
        # authentication function.  See Section 14.4 for codepoint
        # assignments.
        if self.key_id not in (KEY_ID_NONE, KEY_ID_HMAC_SHA_1_96,
                               KEY_ID_HMAC_SHA_256_128):
            raise ValueError('Invalid Key ID')

        # Authentication Data:  The message digest used from the output of the
        # Message Authentication Code (MAC) algorithm.  The entire Map-
        # Register payload is authenticated with this field preset to 0.
        # After the MAC is computed, it is placed in this field.
        # Implementations of this specification MUST include support for
        # HMAC-SHA-1-96 [RFC2404] and support for HMAC-SHA-256-128 [RFC6234]
        # is RECOMMENDED.
        if not isinstance(self.authentication_data, bytes):
            raise ValueError('Invalid nonce')

        # Map-Reply Record:  When the M bit is set, this field is the size of a
        # single "Record" in the Map-Reply format.  This Map-Reply record
        # contains the EID-to-RLOC mapping entry associated with the Source
        # EID.  This allows the ETR which will receive this Map-Request to
        # cache the data if it chooses to do so.
        for record in self.records:
            if not isinstance(record, MapReplyRecord):
                raise ValueError('Invalid record')

            record.sanitize()

    def calculate_authentication_data(self, key):
        '''
        Calculate the authentication data based on the current key-id and the
        given key.
        '''
        # This one is easy
        if self.key_id == KEY_ID_NONE:
            return ''

        # Determine the digestmod and how long the authentication data will be
        if self.key_id == KEY_ID_HMAC_SHA_1_96:
            digestmod = hashlib.sha1
            data_length = 20
        elif self.key_id == KEY_ID_HMAC_SHA_256_128:
            digestmod = hashlib.sha256
            data_length = 32
        else:
            raise ValueError('Unknown Key ID')

        # Fill the authentication data with the right number of zeroes
        # after storing the original first so we can restore it later
        current_authentication_data = self.authentication_data
        self.authentication_data = '\x00' * data_length

        # Build the packet
        msg = self.to_bytes()

        # Restore the authentication data
        self.authentication_data = current_authentication_data

        # Return the authentication data based on the generated packet
        # and the given key
        return hmac.new(key, msg, digestmod).digest()

    def verify_authentication_data(self, key):
        '''
        Verify the current authentication data based on the current key-id and
        the given key.
        '''
        correct_authentication_data = self.calculate_authentication_data(key)
        return self.authentication_data == correct_authentication_data

    def insert_authentication_data(self, key):
        '''
        Insert authentication data based on the current key-id and the given
        key.
        '''
        correct_authentication_data = self.calculate_authentication_data(key)
        self.authentication_data = correct_authentication_data

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

        # Read the type
        type_nr = bitstream.read('uint:4')
        if type_nr != packet.message_type:
            msg = 'Invalid bitstream for a {0} packet'
            class_name = packet.__class__.__name__
            raise ValueError(msg.format(class_name))

        # Read the flags
        packet.proxy_map_reply = bitstream.read('bool')

        # Skip reserved bits
        bitstream.read(18)

        # Read the rest of the flags
        packet.want_map_notify = bitstream.read('bool')

        # Store the record count until we need it
        record_count = bitstream.read('uint:8')

        # Read the nonce
        packet.nonce = bitstream.read('bytes:8')

        # Read the key id
        packet.key_id = bitstream.read('uint:16')

        # Read the authentication data
        data_length = bitstream.read('uint:16')
        packet.authentication_data = bitstream.read('bytes:%d' % data_length)

        # Read the records
        for dummy in range(record_count):
            record = MapReplyRecord.from_bytes(bitstream)
            packet.records.append(record)

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
        bitstream += BitArray('bool=%d' % self.proxy_map_reply)

        # Add padding
        bitstream += BitArray(18)

        # Add the rest of the flags
        bitstream += BitArray('bool=%d' % self.want_map_notify)

        # Add record count
        bitstream += BitArray('uint:8=%d' % len(self.records))

        # Add the nonce
        bitstream += BitArray(bytes=self.nonce)

        # Add the key-id and authentication data
        bitstream += BitArray('uint:16=%d, uint:16=%d, hex=%s'
                              % (self.key_id,
                                 len(self.authentication_data),
                                 self.authentication_data.encode('hex')))

        # Add the map-reply records
        for record in self.records:
            bitstream += record.to_bitstream()

        return bitstream.bytes


# Register this class in the registry
type_registry.register_type_class(MapRegisterMessage)
