'''
Created on 2 jun. 2013

@author: sander
'''
from pylisp.application.lispd.address_tree.base import AbstractNode
from pylisp.application.lispd.map_server_registration import MapServerRegistration
from pylisp.application.lispd.send_message import send_message
from pylisp.packet.lisp.control.locator_record import LocatorRecord
from pylisp.packet.lisp.control.map_register import MapRegisterMessage
from pylisp.packet.lisp.control.map_register_record import MapRegisterRecord
import copy
import logging
import os
import time


# Get the logger
logger = logging.getLogger(__name__)


class ETRNode(AbstractNode):
    def __init__(self, prefix, locators=None, map_servers=None):
        super(ETRNode, self).__init__(prefix)

        # Store copies so that the state doesn't get mixed up if the caller re-uses the same locator
        # and map-server object multiple times
        self.locators = copy.deepcopy(locators) or []
        self.map_servers = copy.deepcopy(map_servers) or []

        if not self.locators:
            logger.warn(u"No Locators defined for prefix {0}".format(self.prefix))

        if not self.map_servers:
            logger.warn(u"No Map-Servers defined for prefix {0}".format(self.prefix))

        for locator in self.locators:
            if not isinstance(locator, LocatorRecord):
                raise ValueError(u"Locator data must be instance of LocatorRecord")

        for ms_data in self.map_servers:
            if not isinstance(ms_data, MapServerRegistration):
                raise ValueError(u"Map-Server data must be instance of MapServerRegistration")

    def process(self, my_sockets):
        super(ETRNode, self).process(my_sockets)

        now = time.time()

        # Copy locators and adjust
        locators = copy.deepcopy(self.locators)

        # Pretend that all locators are reachable
        # TODO: implement something better
        for locator in locators:
            locator.probed_locator = False
            locator.reachable = True

        record = MapRegisterRecord(ttl=1440,
                                   authoritative=True,
                                   eid_prefix=self.prefix,
                                   locator_records=locators)

        for ms_data in self.map_servers:
            assert isinstance(ms_data, MapServerRegistration)

            with ms_data.lock:
                # Do we want to send to this Map-Server?
                if now - ms_data.last_notify > 300:
                    # Map-Notify was a long time ago, try to get one
                    logger.info(u"We would like a Map-Notify for {0} from {1}"
                                ", requesting one".format(self.prefix, ms_data.map_server))
                    want_map_notify = True
                else:
                    if now - ms_data.last_sent < 60:
                        # We sent one in the last minute, don't resend right now
                        continue
                    else:
                        logger.info(u"Sending a Map-Register for {0} to {1}".format(self.prefix, ms_data.map_server))
                        want_map_notify = False

                # Remember the nonce
                nonce = os.urandom(8)
                ms_data.last_nonce = nonce

                # Build the map-register message
                message = MapRegisterMessage(proxy_map_reply=ms_data.proxy_map_reply,
                                             want_map_notify=want_map_notify,
                                             nonce=nonce,
                                             key_id=ms_data.key_id,
                                             authentication_data=ms_data.key,
                                             records=[record])
                message.insert_authentication_data(ms_data.key)

                send_message(message=message,
                             my_sockets=my_sockets,
                             destinations=[ms_data.map_server],
                             port=4342)

                # Remember that we sent one
                ms_data.last_sent = now
