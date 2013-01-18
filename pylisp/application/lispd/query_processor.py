'''
Created on 15 jan. 2013

@author: sander
'''

from pylisp.packet.ip.ipv4 import IPv4Packet
from pylisp.packet.ip.ipv6.base import IPv6Packet
from pylisp.packet.ip.udp import UDPMessage
from pylisp.packet.lisp.control.encapsulated_control_message import \
    LISPEncapsulatedControlMessage
from pylisp.packet.lisp.control.map_request import LISPMapRequestMessage
import threading
from pylisp.packet.lisp.control.map_reply import LISPMapReplyMessage
from pylisp.packet.lisp.control.map_reply_record import LISPMapReplyRecord
from IPy import IP
from pylisp.packet.lisp.control.locator_record import LISPLocatorRecord
import socket


_last_name_id = 0
_last_name_id_lock = threading.Lock()


def _get_new_name():
    global _last_name_id
    global last_name_id_lock

    with _last_name_id_lock:
        _last_name_id += 1
        return 'QueryPocessor-%d' % _last_name_id


class QueryProcessor(threading.Thread):
    def __init__(self, sockets, request, group=None, verbose=None):
        name = _get_new_name()
        threading.Thread.__init__(self, group=group, name=name,
                                  verbose=verbose)
        self.sockets = sockets
        self.request = request

    def run(self):
        if not isinstance(self.request, LISPEncapsulatedControlMessage):
            print('Unhandled %s' % self.request.__class__.__name__)
            return

        print('ECM')
        if self.request.ddt_originated:
            print('DDT')
            return

        print('Non-DDT')
        if isinstance(self.request.payload, IPv4Packet):
            print('IPv4-encap')
        elif isinstance(self.request.payload, IPv6Packet):
            print('IPv6-encap')
        else:
            print('Unknown-encap')
            return

        ip_packet = self.request.payload
        (proto, layer_7) = ip_packet.get_final_payload()
        if not isinstance(layer_7, UDPMessage):
            print('Proto %d' % proto)

        print('UDP')
        req = layer_7.payload
        if not isinstance(req, LISPMapRequestMessage):
            print('Unhandled %s' % req.__class__.__name__)

        print "Request: %r" % req

        locators = [LISPLocatorRecord(priority=10,
                                      weight=100,
                                      local=False,
                                      locator=IP('192.0.2.123'))]
        records = [LISPMapReplyRecord(ttl=123,
                                      authoritative=False,
                                      map_version=0,
                                      eid_prefix=IP(ip_packet.destination)
                                                 .make_net(24),
                                      locator_records=locators)]
        reply = LISPMapReplyMessage(nonce=req.nonce,
                                    records=records)

        addr = None
        sock = None
        for possible_rloc in req.itr_rlocs:
            for possible_sock in self.sockets:
                if possible_rloc.version() == 4 \
                and possible_sock.family == socket.AF_INET:
                    addr = (possible_rloc.strNormal(), layer_7.source_port)
                    sock = possible_sock
                    break

                elif possible_rloc.version() == 6 \
                and possible_sock.family == socket.AF_INET6:
                    addr = (possible_rloc.strNormal(), layer_7.source_port)
                    sock = possible_sock
                    break

            if addr and sock:
                break

        print("Sending reply: %r to %r" % (reply, addr))

        sock.sendto(bytes(reply), addr)
