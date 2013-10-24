import logging
logging_level = logging.DEBUG
logging.basicConfig(level=logging_level, format='%(asctime)s [%(module)s %(levelname)s] %(message)s')

import pylisp.utils.auto_addresses
import pylisp.utils.events

a4 = pylisp.utils.auto_addresses.AutoIPv4Address('en0')
a6 = pylisp.utils.auto_addresses.AutoIPv6Address('en0')
s4 = pylisp.utils.auto_addresses.AutoUDPSocket(a4, 12345)
s6 = pylisp.utils.auto_addresses.AutoUDPSocket(a6, 12345)

pylisp.utils.auto_addresses.update_addresses()
