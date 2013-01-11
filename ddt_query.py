#!/usr/bin/env python
'''
Created on 11 jan. 2013

@author: sander
'''

from IPy import IP
from pylisp.packet.ip import IPv4Packet, IPv6Packet, UDPMessage
from pylisp.packet.lisp.control import LISPEncapsulatedControlMessage, \
    LISPMapRequestMessage, LISPControlMessage
import random
import socket
import sys

my_name = socket.getfqdn()
query = IP(sys.argv[1])
#if query.version() == 4:
#    query_source = IP('37.77.56.75')
#else:
#    query_source = IP('2a00:8640:1:0:224:36ff:feef:1d89')
query_source = IP('::', query.version())

source_port = 4342

# Build the map request
nonce = ''.join([chr(random.choice(xrange(256))) for i in range(8)])

d_addrs = socket.getaddrinfo('mu.ddt-root.net', 4342, 0, 0, socket.SOL_UDP)
for d_family, d_socktype, d_proto, d_canonname, d_sockaddr in d_addrs:
    destination = IP(d_sockaddr[0])

    s_addrs = socket.getaddrinfo(my_name, source_port, d_family, d_socktype, d_proto)
    for s_family, s_socktype, s_proto, s_canonname, s_sockaddr in s_addrs:
        source = IP(s_sockaddr[0])
        print 'From %s to %s' % (source, destination)

        # Build packet
        req = LISPMapRequestMessage(nonce=nonce,
                                    source_eid=query_source,
                                    itr_rlocs=[source],
                                    eid_prefixes=query)
        udp = UDPMessage(source_port=source_port,
                         destination_port=4342,
                         payload=req)
        udp.checksum = udp.calculate_checksum(source=query_source,
                                              destination=query)
        if query.version() == 4:
            ecm_content = IPv4Packet(ttl=64,
                                     protocol=udp.header_type,
                                     source=query_source,
                                     destination=query,
                                     payload=udp)
        elif query.version() == 6:
            ecm_content = IPv6Packet(next_header=udp.header_type,
                                     hop_limit=64,
                                     source=query_source,
                                     destination=query,
                                     payload=udp)

        ecm = LISPEncapsulatedControlMessage(ddt_originated=True,
                                             payload=ecm_content)

        try:
            print 'Sending request:\n%r\n' % ecm
            sock = socket.socket(d_family, d_socktype, d_proto)
            sock.bind(s_sockaddr)
            sock.sendto(bytes(ecm), d_sockaddr)
            data = sock.recv(4096)
            response = LISPControlMessage.from_bytes(data)
            print 'Received reply:\n%r\n' % response
        except socket.error:
            continue
