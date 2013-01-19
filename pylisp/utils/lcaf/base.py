'''
Created on 6 jan. 2013

@author: sander
'''
from abc import ABCMeta, abstractmethod
from bitstring import ConstBitStream, BitArray, Bits
from pylisp.packet.ip.protocol import ProtocolElement


class LCAFAddress(ProtocolElement):
    __metaclass__ = ABCMeta

    lcaf_type = None

    def __init__(self):
        '''
        Constructor
        '''

    @abstractmethod
    def sanitize(self):
        pass

    @classmethod
    def from_bytes(cls, bitstream, prefix_len=None):
        '''
        Look at the type of the message, instantiate the correct class and
        let it parse the message.
        '''
        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Skip the reserved bits
        rsvd1 = bitstream.read(8)

        # Read the flags (and ignore them, no flags are defined yet)
        flags = bitstream.readlist('8*bool')

        # Read the type
        type_nr = bitstream.read('uint:8')

        # Skip the reserved bits
        rsvd2 = bitstream.read(8)

        # Read the length
        length = bitstream.read('uint:16')

        # Read the data
        data = bitstream.read(length * 8)

        # Look for the right class
        from pylisp.utils.lcaf import type_registry
        type_class = type_registry.get_type_class(type_nr)
        if not type_class:
            raise ValueError("Can't handle LCAF type {0}".format(type_nr))

        # Let the specific class handle it from now on
        return type_class._from_data_bytes(data, prefix_len,
                                           rsvd1, flags, rsvd2)

    def to_bytes(self):
        '''
        Create bytes from properties
        '''
        # Check properties
        self.sanitize()

        # Start with reserved bits
        bitstream = self._to_rsvd1()

        # Add zeroes for the flags
        bitstream += self._to_flags()

        # Add the type
        bitstream += BitArray('uint:8=%d' % self.lcaf_type)

        # Some more reserved bits
        bitstream += self._to_rsvd2()

        # Construct the data
        data = self._to_data_bytes()

        # Add the length
        data_length = data.len / 8
        bitstream += BitArray('uint:16=%d' % data_length)

        return (bitstream + data).bytes

    @classmethod
    @abstractmethod
    def _from_data_bytes(cls, data, prefix_len=None, rsvd1=None, flags=None,
                         rsvd2=None):
        '''
        The LCAF header has been parsed, now parse the data
        '''

    def _to_rsvd1(self):
        return BitArray(8)

    def _to_flags(self):
        return BitArray(8)

    def _to_rsvd2(self):
        return BitArray(8)

    @abstractmethod
    def _to_data_bytes(self):
        '''
        The LCAF header has been generated, now generate the data
        '''


#    elif lcaf_type == 4:
#        tos_tc_flowlabel = data.read('uint:24')
#        protocol = data.read('uint:8')
#        local_port, remote_port = data.readlist('2*uint:16')
#        address = read_afi_address_from_bitstream(data)
#        return {'tos_tc_flowlabel': tos_tc_flowlabel,
#                'protocol': protocol,
#                'local_port': local_port,
#                'remote_port': remote_port,
#                'address': address}
#    elif lcaf_type == 6:
#        return {'key': data.bytes}
#    else:
#        # Just give back the damn data
#        return {'type': lcaf_type,
#                'data': data.bytes}
