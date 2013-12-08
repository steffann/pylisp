'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import ip_address
from pylisp.packet.lisp.control.constants import KEY_ID_NONE
import logging


# Get the logger
logger = logging.getLogger(__name__)


class MapServerRegistration(object):
    def __init__(self, map_server, key_id=KEY_ID_NONE, key=None, proxy_map_reply=False, use_rtr=None):
        # Config data
        self.map_server = ip_address(map_server)
        self.key_id = int(key_id)
        self.key = key
        self.proxy_map_reply = bool(proxy_map_reply)
        if use_rtr is None:
            self.use_rtr = None
        else:
            self.use_rtr = bool(use_rtr)

        if self.key_id and not self.key:
            logger.warn("Key-ID but no Key defined for Map-Server {0}".format(self.map_server))

    def __repr__(self):
        return u"MapServerRegistration({0!r})".format(self.map_server)
