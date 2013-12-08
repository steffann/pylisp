from ipaddress import IPv4Address
from pylisp.application.lispd.address_tree.container_node import ContainerNode
from pylisp.application.lispd.address_tree.etr_node import ETRNode
from pylisp.application.lispd.map_server_registration import MapServerRegistration
from pylisp.packet.lisp.control import LocatorRecord, KEY_ID_HMAC_SHA_1_96
from pylisp.utils.auto_addresses import AutoIPv4Address, AutoIPv6Address

# LISTEN_ON = [IPv4Address(u'95.97.83.90')]

# Use one object for the addresses to keep everything consistent
my_ipv4 = AutoIPv4Address('eth0')
my_ipv6 = AutoIPv6Address('eth0')
LISTEN_ON = [my_ipv4, my_ipv6]

# # Load the DDT-Root
# from pylisp.application.lispd.utils.ddt_root_loader import load_ddt_root
# import os.path
#
# INSTANCES = load_ddt_root(os.path.join(os.path.dirname(__file__), 'ddt_root'))

locators = [LocatorRecord(priority=1, weight=100, address=my_ipv4),
            LocatorRecord(priority=1, weight=100, address=my_ipv6)]

key_id = KEY_ID_HMAC_SHA_1_96
key = 'devdevdev'
map_servers = [MapServerRegistration(u'83.247.10.218', key_id=key_id, key=key, proxy_map_reply=True),
               MapServerRegistration(u'87.195.109.18', key_id=key_id, key=key, proxy_map_reply=True)]

INSTANCES = {
    0: {
        1: ContainerNode(u'0.0.0.0/0', [
               ETRNode(u'37.77.57.120/29', locators=locators, map_servers=map_servers)
           ]),
        2: ContainerNode(u'::/0', [
               ETRNode(u'2a00:8640:100d::/48', locators=locators, map_servers=map_servers)
           ]),
       }
}

# Using iptables to intercept outbound traffic:
#  iptables --table mangle --append POSTROUTING -s 37.77.57.120/29 --out-interface eth0 -j NFQUEUE --queue-num 1
#  ip6tables --table mangle --append POSTROUTING -s 2a00:8640:100d::/48 --out-interface eth0 -j NFQUEUE --queue-num 2
#
# Setting a fake default route for IPv6:
#  ip -6 route add default dev eth0
#
# Setting up interface dummy0 with:
#  modprobe dummy
#  ip -4 addr add 37.77.57.120/32 dev dummy0
#  ip -6 addr add 2a00:8640:100d::1/128 dev dummy0

PETR = IPv4Address(u'37.77.56.1')
NFQUEUE_IPV4 = 1
NFQUEUE_IPV6 = 2
