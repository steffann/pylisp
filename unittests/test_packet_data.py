#!/usr/bin/env python
from unittests.utils import PacketTestCreator, PacketTest

# Add the parent directory to the start of the path
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '.')
    sys.path.insert(0, '..')

from pylisp.packet.lisp import data
import doctest
import unittest


def load_tests(loader, tests, ignore):
    '''
    Add doctests to the test set
    '''
    tests.addTests(doctest.DocTestSuite(data))
    return tests


class DataPacketTestCase(unittest.TestCase):
    __metaclass__ = PacketTestCreator

    cases = [PacketTest(name='test_empty_packet',
                        desc='Generate a completely empty packet',
                        cls=data.LISPDataPacket,
                        params={},
                        bytes_hex='0000000000000000',
                        exception=(None, '')),

             PacketTest(name='test_echo_nonce_request',
                        desc='Generate a packet with echo_nonce_request=True, '
                             'which should be ignored because there is no '
                             'nonce',
                        cls=data.LISPDataPacket,
                        params={'echo_nonce_request': True},
                        bytes_hex='0000000000000000',
                        exception=(None, '')),

             PacketTest(name='test_echo_nonce_request_with_nonce',
                        cls=data.LISPDataPacket,
                        desc='Generate a packet with echo_nonce_request=True '
                             'and a valid nonce',
                        params={'echo_nonce_request': True,
                                'nonce': 'ABC'},
                        bytes_hex='a041424300000000',
                        exception=(None, '')),

             PacketTest(name='test_bad_echo_nonce_request',
                        desc='Generate a packet with echo_nonce_request=None',
                        cls=data.LISPDataPacket,
                        params={'echo_nonce_request': None},
                        bytes_hex='',
                        exception=(ValueError, 'boolean')),

             PacketTest(name='test_nonce',
                        desc='Generate a packet with a valid nonce',
                        cls=data.LISPDataPacket,
                        params={'nonce': 'ABC'},
                        bytes_hex='8041424300000000',
                        exception=(None, '')),

             PacketTest(name='test_bad_nonce',
                        desc='Generate a packet with an invalid nonce',
                        cls=data.LISPDataPacket,
                        params={'nonce': 'ABCDEFGH'},
                        bytes_hex='',
                        exception=(ValueError, 'sequence')),

             PacketTest(name='test_source_map_version',
                        desc='Generate a packet with a valid '
                             'source_map_version but no '
                             'destination_map_version',
                        cls=data.LISPDataPacket,
                        params={'source_map_version': 1234},
                        bytes_hex='',
                        exception=(ValueError, 'destination')),

             PacketTest(name='test_destination_map_version',
                        desc='Generate a packet with no '
                             'source_map_version but a valid '
                             'destination_map_version',
                        cls=data.LISPDataPacket,
                        params={'destination_map_version': 1234},
                        bytes_hex='',
                        exception=(ValueError, 'source')),

             PacketTest(name='test_source_and_destination_map_version',
                        desc='Generate a packet with a valid '
                             'source_map_version and a valid '
                             'destination_map_version',
                        cls=data.LISPDataPacket,
                        params={'source_map_version': 0x123,
                                'destination_map_version': 0x456},
                        bytes_hex='1012345600000000',
                        exception=(None, '')),

             PacketTest(name='test_nonce_and_map_version',
                        desc='Generate a packet with a valid '
                             'source_map_version and a valid '
                             'destination_map_version and a valid nonce, '
                             'which in total is not valid',
                        cls=data.LISPDataPacket,
                        params={'nonce': 'XYZ',
                                'source_map_version': 0x123,
                                'destination_map_version': 0x456},
                        bytes_hex='',
                        exception=(ValueError, 'nonce.*version')),

             PacketTest(name='test_bad_source_map_version',
                        desc='Generate a packet with an invalid '
                             'source_map_version and a valid '
                             'destination_map_version',
                        cls=data.LISPDataPacket,
                        params={'source_map_version': 9999,
                                'destination_map_version': 1234},
                        bytes_hex='',
                        exception=(ValueError, 'source')),

             PacketTest(name='test_bad_destination_map_version',
                        desc='Generate a packet with a valid '
                             'source_map_version and an invalid '
                             'destination_map_version',
                        cls=data.LISPDataPacket,
                        params={'source_map_version': 1234,
                                'destination_map_version': 9999},
                        bytes_hex='',
                        exception=(ValueError, 'destination')),

             PacketTest(name='test_lsb',
                        desc='Generate a packet with alternating True/False'
                             'LSBs',
                        cls=data.LISPDataPacket,
                        params={'lsb': [True, False] * 16},
                        bytes_hex='4000000055555555',
                        exception=(None, '')),

             PacketTest(name='test_bad_lsb_content',
                        desc='Generate a packet with invalid LSBs content',
                        cls=data.LISPDataPacket,
                        params={'lsb': [True, 'False'] * 16},
                        bytes_hex='',
                        exception=(ValueError, 'status.bits')),

             PacketTest(name='test_bad_lsb_length',
                        desc='Generate a packet with invalid LSBs length',
                        cls=data.LISPDataPacket,
                        params={'lsb': [True, False] * 8},
                        bytes_hex='',
                        exception=(ValueError, 'status.bits')),

             PacketTest(name='test_instance_id',
                        desc='Generate a packet with an instance-id',
                        cls=data.LISPDataPacket,
                        params={'instance_id': 11259375},
                        bytes_hex='08000000abcdef00',
                        exception=(None, '')),

             PacketTest(name='test_bad_instance_id',
                        desc='Generate a packet with an invalid instance-id',
                        cls=data.LISPDataPacket,
                        params={'instance_id': 112593750},
                        bytes_hex='',
                        exception=(ValueError, 'instance.id')),

             PacketTest(name='test_lsb_and_instance_id',
                        desc='Generate a packet with LSB and an instance-id',
                        cls=data.LISPDataPacket,
                        params={'instance_id': 11259375,
                                'lsb': [True, False] * 4},
                        bytes_hex='48000000abcdef55',
                        exception=(None, '')),

             PacketTest(name='test_bad_lsb_and_instance_id',
                        desc='Generate a packet with invalid lsb length and an'
                             ' instance-id',
                        cls=data.LISPDataPacket,
                        params={'instance_id': 11259375,
                                'lsb': [True, False] * 16},
                        bytes_hex='',
                        exception=(ValueError, 'status.bits')),

             PacketTest(name='test_payload',
                        desc='Generate a packet with payload',
                        cls=data.LISPDataPacket,
                        params={'payload': 'SomePayload'},
                        bytes_hex='0000000000000000536f6d655061796c6f6164',
                        exception=(None, '')),

             ]


suite = unittest.TestLoader().loadTestsFromTestCase(DataPacketTestCase)


if __name__ == '__main__':
    unittest.main()
