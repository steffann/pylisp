import logging
logging_level = logging.DEBUG
logging.basicConfig(level=logging_level, format='%(asctime)s [%(module)s %(levelname)s] %(message)s')

from pylisp.utils.auto_addresses import get_ipv4_address, get_ipv6_address
from pylisp.application.lispd.address_tree.etr_node import *

locators = [LocatorRecord(priority=1, weight=100, address=get_ipv4_address('eth0')),
            LocatorRecord(priority=1, weight=100, address=get_ipv6_address('eth0'))]

msr = MapServerRegistration(u'10.0.1.2')

etr = ETRNode(u'10.0.0.0/24', map_servers=[msr], locators=locators)
