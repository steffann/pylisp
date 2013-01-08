#!/usr/bin/env python

# Add the parent directory to the start of the path
if __name__ == '__main__':
    import sys
    sys.path.insert(0, '.')
    sys.path.insert(0, '..')

from pylisp.packet import data
import doctest
import unittest


def load_tests(loader, tests, ignore):
    '''
    Add doctests to the test set
    '''
    tests.addTests(doctest.DocTestSuite(data))
    return tests


class DataPacketTestCase(unittest.TestCase):
    def test_empty_packet(self):
        '''
        Generate a completely empty packet
        '''
        message = data.LISPDataPacket()
        self.assertEqual('\x00\x00\x00\x00\x00\x00\x00\x00',
                         message.to_bytes())

    def test_echo_nonce_request(self):
        '''
        Generate a packet with echo_nonce_request=True, which should be
        ignored because there is no nonce
        '''
        message = data.LISPDataPacket(echo_nonce_request=True)
        self.assertEqual('\x00\x00\x00\x00\x00\x00\x00\x00',
                         message.to_bytes())

    def test_echo_nonce_request_with_nonce(self):
        '''
        Generate a packet with echo_nonce_request=True and a valid nonce
        '''
        message = data.LISPDataPacket(echo_nonce_request=True, nonce='ABC')
        self.assertEqual('\xa0ABC\x00\x00\x00\x00',
                         message.to_bytes())

    def test_bad_echo_nonce_request(self):
        '''
        Generate a packet with echo_nonce_request=None
        '''
        with self.assertRaisesRegexp(ValueError, 'boolean'):
            message = data.LISPDataPacket(echo_nonce_request=None)
            message.sanitize()

    def test_nonce(self):
        '''
        Generate a packet with a valid nonce
        '''
        message = data.LISPDataPacket(nonce='ABC')
        self.assertEqual('\x80ABC\x00\x00\x00\x00',
                         message.to_bytes())

    def test_bad_nonce(self):
        '''
        Generate a packet with an invalid nonce
        '''
        with self.assertRaisesRegexp(ValueError, 'nonce'):
            message = data.LISPDataPacket(nonce='ABCDEFGH')
            message.sanitize()

    def test_source_map_version(self):
        '''
        Generate a packet with a valid source_map_version but no
        destination_map_version
        '''
        with self.assertRaisesRegexp(ValueError, 'destination'):
            message = data.LISPDataPacket(source_map_version=1234)
            message.sanitize()

    def test_destination_map_version(self):
        '''
        Generate a packet with a valid destination_map_version but no
        source_map_version
        '''
        with self.assertRaisesRegexp(ValueError, 'source'):
            message = data.LISPDataPacket(destination_map_version=1234)
            message.sanitize()

    def test_source_and_destination_map_version(self):
        '''
        Generate a packet with a valid source_map_version and a valid
        destination_map_version
        '''
        message = data.LISPDataPacket(source_map_version=1234,
                                      destination_map_version=2345)
        self.assertEqual('\x10M))\x00\x00\x00\x00',
                         message.to_bytes())

    def test_bad_source_map_version(self):
        '''
        Generate a packet with an invalid source_map_version and a valid
        destination_map_version
        '''
        with self.assertRaisesRegexp(ValueError, 'source'):
            message = data.LISPDataPacket(source_map_version=9999,
                                          destination_map_version=2345)
            message.sanitize()

    def test_bad_destination_map_version(self):
        '''
        Generate a packet with a valid source_map_version and an invalid
        destination_map_version
        '''
        with self.assertRaisesRegexp(ValueError, 'destination'):
            message = data.LISPDataPacket(source_map_version=1234,
                                          destination_map_version=9999)
            message.sanitize()

    def test_lsb(self):
        '''
        Generate a packet with alternating True/False LSBs
        '''
        lsb = [True, False] * 16
        message = data.LISPDataPacket(lsb=lsb)
        self.assertEqual('@\x00\x00\x00UUUU',
                         message.to_bytes())

    def test_bad_lsb_content(self):
        '''
        Generate a packet with invalid LSBs content
        '''
        lsb = [True, 'False'] * 16
        with self.assertRaisesRegexp(ValueError, 'status.bits'):
            message = data.LISPDataPacket(lsb=lsb)
            message.sanitize()

    def test_bad_lsb_length(self):
        '''
        Generate a packet with invalid LSBs length
        '''
        lsb = [True, False] * 8
        with self.assertRaisesRegexp(ValueError, 'status.bits'):
            message = data.LISPDataPacket(lsb=lsb)
            message.sanitize()

    def test_instance_id(self):
        '''
        Generate a packet with an instance-id
        '''
        message = data.LISPDataPacket(instance_id=11259375)
        self.assertEqual('\x08\x00\x00\x00\xab\xcd\xef\x00',
                         message.to_bytes())

    def test_bad_instance_id(self):
        '''
        Generate a packet with an invalid instance-id
        '''
        with self.assertRaisesRegexp(ValueError, 'instance.id'):
            message = data.LISPDataPacket(instance_id=112593750)
            message.sanitize()

    def test_lsb_and_instance_id(self):
        '''
        Generate a packet with lsb and an instance-id
        '''
        lsb = [True, False] * 4
        message = data.LISPDataPacket(lsb=lsb, instance_id=11259375)
        self.assertEqual('H\x00\x00\x00\xab\xcd\xefU',
                         message.to_bytes())

    def test_bad_lsb_and_instance_id(self):
        '''
        Generate a packet with invalid lsb length and an instance-id
        '''
        lsb = [True, False] * 16
        with self.assertRaisesRegexp(ValueError, 'status.bits'):
            message = data.LISPDataPacket(lsb=lsb, instance_id=11259375)
            message.sanitize()

    def test_payload(self):
        '''
        Generate a packet with payload
        '''
        message = data.LISPDataPacket(payload='SomeDummyPayload')
        self.assertEqual('\x00\x00\x00\x00\x00\x00\x00\x00SomeDummyPayload',
                         message.to_bytes())


suite = unittest.TestLoader().loadTestsFromTestCase(DataPacketTestCase)


if __name__ == '__main__':
    unittest.main()
