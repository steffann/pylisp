#!/usr/bin/env python
from pylisp.packet.data import LISPDataPacket
from pylisp.packet.control.base import LISPControlPacket

print '-------------------------------------------------'
print 'Testing parsing and re-constructing a data packet'
print '-------------------------------------------------'

data_packet_hex = ('c033d3c10000000745c0005835400000' +
                   'ff06094a254d38204d45d1a30016f597' +
                   'a1c3c7406718bf1b50180ff0793f0000' +
                   'b555e59ff5ba6aad33d875c600fd8c1f' +
                   'c5268078f365ee199179fbd09d09d690' +
                   '193622a6b70bcbc7bf5f20dda4258801')

data_packet = data_packet_hex.decode('hex')

print 'Parsing...'
packet = LISPDataPacket.from_bytes(data_packet)
print 'Parsed', packet.__class__.__name__, packet
print 'Reconstructing...'
packet_bin = packet.to_bytes()
assert(data_packet == packet_bin)
print 'Reconstructed packet matches original'


control_packets_hex = [('13000001ae92b5574f849cd00001ac10' +
                        '1f0300015cfe1cbd00200001ac101f01'),
                       ('28000001ae92b5574f849cd0000005a0' +
                        '0120100000000001ac101f010064ff00' +
                        '00070001d41ac503')]

for control_packet_hex in control_packets_hex:
    print '----------------------------------------------------'
    print 'Testing parsing and re-constructing a control packet'
    print '----------------------------------------------------'

    control_packet = control_packet_hex.decode('hex')

    print 'Parsing...'
    message = LISPControlPacket.from_bytes(control_packet)
    print 'Parsed', message.__class__.__name__, message
    print 'Reconstructing...'
    message_bin = message.to_bytes()
    assert(control_packet == message_bin)
    print 'Reconstructed packet matches original'
