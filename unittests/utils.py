'''
Created on 8 jan. 2013

@author: sander
'''


class PacketTest(object):
    def __init__(self, name, desc, cls, params, bytes_hex, exception):
        self.name = name
        self.desc = desc
        self.cls = cls
        self.params = params
        self.bytes_hex = bytes_hex
        self.exception = exception


class PacketTestCreator(type):
    def __new__(cls, name, bases, dct):
        '''
        Create methods for test cases
        '''
        for case in dct['cases']:
            test_name = case.name

            # Check for duplicate names
            if test_name in dct:
                raise ValueError('Duplicate test name: %s' % test_name)

            # Build a test-method
            def test_method(self, case):
                exc_class, exc_regex = case.exception

                if exc_class:
                    # Check that the exception is raised properly
                    with self.assertRaisesRegexp(exc_class, exc_regex):
                        message = case.cls(**case.params)
                        message.sanitize()
                else:
                    # Create the packet and check the output
                    message = case.cls(**case.params)
                    message_bytes = message.to_bytes()
                    message_hex = message_bytes.encode('hex')

                    self.assertEqual(message_hex, case.bytes_hex)

                    # Parse expected output to see if we get the same packet
                    packet = case.bytes_hex.decode('hex')
                    message2 = case.cls.from_bytes(packet)

                    self.assertIsInstance(message2, case.cls)
                    self.assertEqual(message2.__dict__, message.__dict__)

            # Wrap it in a lambda and add it to dct
            dct[test_name] = lambda self, case = case: test_method(self, case)

        return super(PacketTestCreator, cls).__new__(cls, name, bases, dct)
