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

ipv6_packet_hex = ('6000000000d611fffe80000000000000'
                   'aafad8fffeec0ea3ff02000000000000'
                   '00000000000000fb'
                   '14e914e900d68227'
                   '0000000000030000000300012a61383a'
                   '66613a64383a65633a30653a61334066'
                   '6538303a3a616166613a643866663a66'
                   '6565633a6561330d5f6170706c652d6d'
                   '6f62646576045f746370056c6f63616c'
                   '0000ff00010f6950686f6e652d76616e'
                   '2d41647269c04a00ff0001c05500ff00'
                   '01c00c00210001000000780008000000'
                   '00f27ec055c055001c00010000007800'
                   '10fe80000000000000aafad8fffeec0e'
                   'a3c05500010001000000780004ac1e00'
                   '7a00002905a00000119400120004000e'
                   '0004aafad8ec0ea3a8fad8ec0ea3')
ipv6_packet = ipv6_packet_hex.decode('hex')

from pylisp.packet.ip.ipv6 import IPv6Packet

packet = IPv6Packet.from_bytes(ipv6_packet)
print packet

pkt_bytes = packet.to_bytes()
pkt_bytes_hex = pkt_bytes.encode('hex')

print ipv6_packet == pkt_bytes

udp_message = UDPMessage.from_bytes(packet.payload)
print udp_message
print udp_message.calculate_checksum(packet.source, packet.destination)

udp_msg_bytes = udp_message.to_bytes()
udp_msg_bytes_hex = udp_msg_bytes.encode('hex')

print packet.payload == udp_msg_bytes

from pylisp.packet.ip.ipv6 import IPv6HopByHopOptionsHeader

hdrbytes_hex = ('00010000000000000000000000000000')
hdrbytes = hdrbytes_hex.decode('hex')
hdr = IPv6HopByHopOptionsHeader.from_bytes(hdrbytes)
print hdr
print hdrbytes_hex
print hdr.to_bytes().encode('hex')
