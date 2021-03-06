'''
Created on 6 jan. 2013

@author: sander
'''
from bitstring import BitArray, ConstBitStream, Bits
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network, \
    ip_network


# Constants
Empty = 0
IPv4 = 1
IPv6 = 2
LCAF = 16387


def read_afi_address_from_bitstream(bitstream, prefix_len=None):
    '''
    This function decodes an AFI address from a readable bitstream:
    >>> from bitstring import ConstBitStream

    This is an example of an IPv4 address:
    >>> afi_address = '0001c00002ab'.decode('hex')
    >>> bitstream = ConstBitStream(bytes=afi_address)
    >>> read_afi_address_from_bitstream(bitstream)
    IPv4Address(u'192.0.2.171')

    If a prefix length is provided then a prefix is returned:
    >>> afi_address = '0001c0000200'.decode('hex')
    >>> bitstream = ConstBitStream(bytes=afi_address)
    >>> read_afi_address_from_bitstream(bitstream, 24)
    IPv4Network(u'192.0.2.0/24')

    The function consumes the bits used by the AFI address from the
    bitstream, but won't read beyond that point:
    >>> bitstream.pos == bitstream.len
    True
    '''

    # Convert to ConstBitStream (if not already provided)
    if not isinstance(bitstream, ConstBitStream):
        if isinstance(bitstream, Bits):
            bitstream = ConstBitStream(auto=bitstream)
        else:
            bitstream = ConstBitStream(bytes=bitstream)

    # Read the source EID
    afi = bitstream.read('uint:16')
    if afi == Empty:
        # No address
        if prefix_len:
            raise ValueError('Empty AFI addresses can not have prefix_len')

        return None

    elif afi == IPv4:
        # IPv4 address
        address_int = bitstream.read('uint:32')
        address = IPv4Address(address_int)
        if prefix_len is not None:
            orig_address = address
            address = ip_network(address).supernet(new_prefix=prefix_len)
            if address[0] != orig_address:
                raise ValueError("invalid prefix length %s for %r"
                                 % (prefix_len, address))

    elif afi == IPv6:
        # IPv6 address
        address_int = bitstream.read('uint:128')
        address = IPv6Address(address_int)
        if prefix_len is not None:
            orig_address = address
            address = ip_network(address).supernet(new_prefix=prefix_len)
            if address[0] != orig_address:
                raise ValueError("invalid prefix length %s for %r"
                                 % (prefix_len, address))

    elif afi == LCAF:
        from pylisp.utils.lcaf import LCAFAddress
        address = LCAFAddress.from_bytes(bitstream, prefix_len)

    else:
        raise ValueError('Unable to handle AFI {0}'.format(afi))

    return address


def get_bitstream_for_afi_address(address):
    from pylisp.utils.lcaf import LCAFAddress

    # No address is AFI 0
    if address is None:
        return BitArray(16)

    # IPv4
    if isinstance(address, IPv4Address):
        return BitArray('uint:16=1, uint:32=%d' % int(address))

    elif isinstance(address, IPv4Network):
        return BitArray('uint:16=1, uint:32=%d' % int(address[0]))

    # IPv6
    elif isinstance(address, IPv6Address):
        return BitArray('uint:16=2, uint:128=%d' % int(address))

    elif isinstance(address, IPv6Network):
        return BitArray('uint:16=2, uint:128=%d' % int(address[0]))

    elif isinstance(address, LCAFAddress):
        address_bytes = bytes(address)
        return BitArray('uint:16=16387') + BitArray(bytes=address_bytes)

    else:
        # Nobody encoded it...
        raise ValueError('Unsupported address type')
