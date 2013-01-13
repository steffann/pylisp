#!/usr/bin/env python
import sys
sys.path.insert(0, '.')
sys.path.insert(0, '..')

from pylisp.packet.ip import IPv4Packet, IPv6Packet

ip_packet_hex = ('45c00078000a0000201173c85cfe1cbdd413d814'
                 '10f610f6006437b6'
                 '300000023ad9b962efd2a781000100147e97ef1d'
                 '97151875d35ba8edcccdc6e676e75ee7000005a0'
                 '0120100000000001ac101f030064ff0000050001'
                 '5cfe1cbd000005a00118100000000001ac102a00'
                 '0064ff00000500015cfe1cbd')
ip_packet = ip_packet_hex.decode('hex')

packet = IPv4Packet.from_bytes(ip_packet)
print repr(packet)

pkt_bytes = bytes(packet)
pkt_bytes_hex = pkt_bytes.encode('hex')

print ip_packet == pkt_bytes

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

packet = IPv6Packet.from_bytes(ipv6_packet)
print repr(packet)

pkt_bytes = packet.to_bytes()
pkt_bytes_hex = pkt_bytes.encode('hex')

print ipv6_packet == pkt_bytes

multilayer_hex = ('45000073f7734000ff1173f95f61535d'
                  '254d380104ce10f5005f0000c0ac1912'
                  '00000007600000000027113e2a008640'
                  '0001000002204afffec8259920010503'
                  '0c2700000000000000020030d21d0035'
                  '0027af7b942700000001000000000000'
                  '08686f73746e616d650462696e640000'
                  '100003')
multilayer = multilayer_hex.decode('hex')

outer = IPv4Packet.from_bytes(multilayer)
print repr(outer)
print bytes(outer).encode('hex')
print multilayer_hex
print bytes(outer) == multilayer
