#!/usr/bin/env python
from pylisp.packet.ip.udp import UDPMessage
from pylisp.packet.control.base import LISPControlMessage

ip_packet_hex = ('45c00078000a0000201173c85cfe1cbdd413d814'
                 '10f610f6006437b6'
                 '300000023ad9b962efd2a781000100147e97ef1d'
                 '97151875d35ba8edcccdc6e676e75ee7000005a0'
                 '0120100000000001ac101f030064ff0000050001'
                 '5cfe1cbd000005a00118100000000001ac102a00'
                 '0064ff00000500015cfe1cbd')
ip_packet = ip_packet_hex.decode('hex')

from pylisp.packet.ip.ipv4 import IPv4Packet

packet = IPv4Packet.from_bytes(ip_packet)
print packet

pkt_bytes = packet.to_bytes()
pkt_bytes_hex = pkt_bytes.encode('hex')

print ip_packet == pkt_bytes

udp_message = UDPMessage.from_bytes(packet.payload)
print udp_message
print udp_message.calculate_checksum(packet.source, packet.destination)

udp_msg_bytes = udp_message.to_bytes()
udp_msg_bytes_hex = udp_msg_bytes.encode('hex')

print packet.payload == udp_msg_bytes

lisp_message = LISPControlMessage.from_bytes(udp_message.payload)
print lisp_message
