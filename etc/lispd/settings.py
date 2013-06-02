from ipaddress import IPv4Address
from pylisp.application.lispd.address_tree import ContainerNode, MapServerClientNode
from pylisp.application.lispd.map_server_registration import MapServerRegistration
from pylisp.packet.lisp.control import LocatorRecord, KEY_ID_HMAC_SHA_1_96

LISTEN_ON = [(IPv4Address(u'95.97.83.91'), 4342)]

# # Load the DDT-Root
# from pylisp.application.lispd.utils.ddt_root_loader import load_ddt_root
# import os.path
#
# INSTANCES = load_ddt_root(os.path.join(os.path.dirname(__file__), 'ddt_root'))

locators = [LocatorRecord(priority=1, weight=100, local=True, reachable=True, locator=IPv4Address(u'95.97.83.91'))]

key_id = KEY_ID_HMAC_SHA_1_96
key = 'devdevdev'
map_servers = [MapServerRegistration(u'83.247.10.218', key_id=key_id, key=key, proxy_map_reply=True),
               MapServerRegistration(u'87.195.109.18', key_id=key_id, key=key, proxy_map_reply=True)]

INSTANCES = {
    0: {
        1: ContainerNode(u'0.0.0.0/0', [
               MapServerClientNode(u'37.77.57.120/29', locators=locators, map_servers=map_servers)
           ]),
        2: ContainerNode(u'::/0', [
               MapServerClientNode(u'2a00:8640:100d::/48', locators=locators, map_servers=map_servers)
           ]),
       }
}
