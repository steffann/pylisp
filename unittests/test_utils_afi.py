#!/usr/bin/env python

# Add the parent directory to the start of the path
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '.')
    sys.path.insert(0, '..')

from IPy import IP
from bitstring import ConstBitStream
from pylisp.utils import afi
import doctest
import unittest


def load_tests(loader, tests, ignore):
    '''
    Add doctests to the test set
    '''
    tests.addTests(doctest.DocTestSuite(afi))
    return tests


class AfiTestCase(unittest.TestCase):
    def test_afi_0_without_prefixlen(self):
        '''
        Test en/decoding of empty AFI addresses
        '''
        afi_address_hex = '0000'
        bitstream = ConstBitStream(hex=afi_address_hex)

        address = afi.read_afi_address_from_bitstream(bitstream)

        self.assertIsNone(address, 'wrong address')
        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

        new_bitstream = afi.get_bitstream_for_afi_address(address)

        self.assertEqual(new_bitstream.tobytes(), bitstream.tobytes())

    def test_afi_0_with_prefixlen(self):
        '''
        Specifying a prefix length for an empty AFI address is invalid
        '''
        bitstream = ConstBitStream(hex='0000')

        with self.assertRaisesRegexp(ValueError, r'prefix'):
            afi.read_afi_address_from_bitstream(bitstream, 16)

        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

    def test_afi_0_with_prefixlen_0(self):
        '''
        Although a prefix length of 0 is allowed (since that is how many
        implementations transmit it on the wire)
        '''
        afi_address_hex = '0000'
        bitstream = ConstBitStream(hex=afi_address_hex)

        address = afi.read_afi_address_from_bitstream(bitstream, 0)

        self.assertIsNone(address, 'wrong address')
        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

        new_bitstream = afi.get_bitstream_for_afi_address(address)

        self.assertEqual(new_bitstream.tobytes(), bitstream.tobytes())

    def test_afi_1_without_prefixlen(self):
        '''
        Test decoding of AFI 1 (IPv4) addresses
        '''
        afi_address_hex = '0001c00002ab'
        bitstream = ConstBitStream(hex=afi_address_hex)

        address = afi.read_afi_address_from_bitstream(bitstream)

        self.assertEqual(address, IP('192.0.2.171'))
        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

        new_bitstream = afi.get_bitstream_for_afi_address(address)

        self.assertEqual(new_bitstream.tobytes(), bitstream.tobytes())

    def test_afi_1_with_prefixlen(self):
        '''
        Test decoding of AFI 1 (IPv4) prefixes
        '''
        afi_address_hex = '0001c0000200'
        bitstream = ConstBitStream(hex=afi_address_hex)

        address = afi.read_afi_address_from_bitstream(bitstream, 24)

        self.assertEqual(address, IP('192.0.2.0/24'))
        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

        new_bitstream = afi.get_bitstream_for_afi_address(address)

        self.assertEqual(new_bitstream.tobytes(), bitstream.tobytes())

    def test_afi_1_with_bad_prefixlen(self):
        '''
        Test decoding of AFI 1 (IPv4) prefixes with a bad prefix length
        '''
        afi_address_hex = '0001c00002ab'
        bitstream = ConstBitStream(hex=afi_address_hex)

        with self.assertRaisesRegexp(ValueError, 'invalid.prefix.length'):
            afi.read_afi_address_from_bitstream(bitstream, 24)

        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

    def test_afi_2_without_prefixlen(self):
        '''
        Test decoding of AFI 2 (IPv6) addresses
        '''
        afi_address_hex = '000220010db80102abcd000000000000cafe'
        bitstream = ConstBitStream(hex=afi_address_hex)

        address = afi.read_afi_address_from_bitstream(bitstream)

        self.assertEqual(address, IP('2001:db8:102:abcd::cafe'))
        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

        new_bitstream = afi.get_bitstream_for_afi_address(address)

        self.assertEqual(new_bitstream.tobytes(), bitstream.tobytes())

    def test_afi_2_with_prefixlen(self):
        '''
        Test decoding of AFI 2 (IPv6) prefixes
        '''
        afi_address_hex = '000220010db80102abcd0000000000000000'
        bitstream = ConstBitStream(hex=afi_address_hex)

        address = afi.read_afi_address_from_bitstream(bitstream, 64)

        self.assertEqual(address, IP('2001:db8:102:abcd::/64'))
        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

        new_bitstream = afi.get_bitstream_for_afi_address(address)

        self.assertEqual(new_bitstream.tobytes(), bitstream.tobytes())

    def test_afi_2_with_bad_prefixlen(self):
        '''
        Test decoding of AFI 2 (IPv6) prefixes with a bad prefix length
        '''
        afi_address_hex = '000220010db80102abcd000000000000cafe'
        bitstream = ConstBitStream(hex=afi_address_hex)

        with self.assertRaisesRegexp(ValueError, 'invalid.prefix.length'):
            afi.read_afi_address_from_bitstream(bitstream, 64)

        self.assertEqual(bitstream.pos, bitstream.len,
                         'unprocessed bits remaining in bitstream')

    def test_afi_65535(self):
        '''
        AFI 65535 is reserved
        '''
        afi_address_hex = 'ffffabcdabcdabcd'
        bitstream = ConstBitStream(hex=afi_address_hex)

        with self.assertRaisesRegexp(ValueError, 'AFI'):
            afi.read_afi_address_from_bitstream(bitstream)

    def test_bad_input_address(self):
        '''
        Ask to encode something that is not an address
        '''
        address = 'Something that is not an address'

        with self.assertRaisesRegexp(ValueError, '[Uu]nsupported'):
            afi.get_bitstream_for_afi_address(address)


suite = unittest.TestLoader().loadTestsFromTestCase(AfiTestCase)


if __name__ == '__main__':
    unittest.main()
