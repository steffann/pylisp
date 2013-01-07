'''
Created on 6 jan. 2013

@author: sander
'''
from IPy import IP
from bitstring import BitArray


def read_afi_address_from_bitstream(bitstream, prefix_len=None):
    '''
    This function decodes an AFI address from a readable bitstream:
    >>> from bitstring import ConstBitStream

    This is an example of an IPv4 address:
    >>> afi_address = '0001c00002ab'.decode('hex')
    >>> bitstream = ConstBitStream(bytes=afi_address)
    >>> read_afi_address_from_bitstream(bitstream)
    IP('192.0.2.171')

    If a prefix length is provided then a prefix is returned:
    >>> afi_address = '0001c0000200'.decode('hex')
    >>> bitstream = ConstBitStream(bytes=afi_address)
    >>> read_afi_address_from_bitstream(bitstream, 24)
    IP('192.0.2.0/24')

    The function consumes the bits used by the AFI address from the
    bitstream, but won't read beyond that point:
    >>> bitstream.pos == bitstream.len
    True
    '''

    # Read the source EID
    afi = bitstream.read('uint:16')
    if afi == 0:
        # No address
        if prefix_len:
            raise ValueError('Empty AFI addresses can not have prefix_len')

        return None

    elif afi == 1:
        # IPv4 address
        address_int = bitstream.read('uint:32')
        address = IP(address_int, ipversion=4)

    elif afi == 2:
        # IPv6 address
        address_int = bitstream.read('uint:128')
        address = IP(address_int, ipversion=6)

    elif afi == 16387:
        raise ValueError('Unable to handle LCAF addresses')

    else:
        raise ValueError('Unable to handle AFI {0}'.format(afi))

    if prefix_len is not None:
        # Make a prefix out of it
        prefix = address.make_net(prefix_len)

        # Check that we didn't blank out any bits
        if address.ip != prefix.ip:
            raise ValueError('AFI address contains bits masked by prefix')

        return prefix
    else:
        return address


def get_bitstream_for_afi_address(address):
    # No address is AFI 0
    if address is None:
        return BitArray(16)

    if not isinstance(address, IP):
        raise ValueError('Unsupported address')

    # IPv4
    if address.version() == 4:
        return BitArray('uint:16=1, uint:32=%d' % address.ip)

    # IPv6
    if address.version() == 6:
        return BitArray('uint:16=2, uint:128=%d' % address.ip)
