'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import ip_address
from pylisp.packet.lisp.control.constants import KEY_ID_NONE
import copy
import logging
import threading


# Get the logger
logger = logging.getLogger(__name__)


class MapServerRegistration(object):
    def __init__(self, map_server, key_id=KEY_ID_NONE, key=None, proxy_map_reply=False):
        # Lock
        self.lock = threading.RLock()

        # Config data
        self.map_server = ip_address(map_server)
        self.key_id = int(key_id)
        self.key = key
        self.proxy_map_reply = bool(proxy_map_reply)

        # Remember the state
        self.last_sent = 0
        self.last_notify = 0
        self.last_nonce = ''

        if self.key_id and not self.key:
            logger.warn("Key-ID but no Key defined for Map-Server {0}".format(self.map_server))

    def __deepcopy__(self, memo):
        # Start with a shallow copy
        my_copy = copy.copy(self)

        # Create a new lock
        my_copy.lock = threading.RLock()

        # Deep copy the map address
        my_copy.map_server = copy.deepcopy(self.map_server, memo)

        return my_copy
