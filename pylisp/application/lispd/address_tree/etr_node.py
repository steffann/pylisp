'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import ip_address
from pylisp.application.lispd.address_tree.base import AbstractNode
from pylisp.application.lispd.map_server_registration import MapServerRegistration
from pylisp.application.lispd.send_message import send_message
from pylisp.packet.lisp.control.info_message import InfoMessage
from pylisp.packet.lisp.control.locator_record import LocatorRecord
from pylisp.packet.lisp.control.map_register import MapRegisterMessage
from pylisp.packet.lisp.control.map_register_record import MapRegisterRecord
from pylisp.utils.auto_addresses import AutoAddress
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
        self.locators = locators or []
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

    def get_locators(self, sockets):
        # Copy locators and adjust
        locators = []
        for locator in self.locators:
            with locator.lock:
                if isinstance(locator.address, AutoAddress):
                    locator.address.update_address()

                if int(locator.address) == 0:
                    continue

                local = False
                for sock in sockets:
                    if int(sock.address) == int(locator.address):
                        local = True
                        break

                locators.append(LocatorRecord(priority=locator.priority,
                                              weight=locator.weight,
                                              m_priority=locator.m_priority,
                                              m_weight=locator.m_weight,
                                              local=local,
                                              reachable=True,
                                              address=ip_address(unicode(locator.address))))

        return locators

    def process(self, control_plane_sockets, data_plane_sockets):
        super(ETRNode, self).process(control_plane_sockets, data_plane_sockets)

        now = time.time()

        record = None
        for ms_data in self.map_servers:
            assert isinstance(ms_data, MapServerRegistration)

            with ms_data.lock:
                # Do we want to send to this Map-Server?
                if now - ms_data.last_notify > 330:
                    # It has been too long, start NAT discovery
                    logger.info(u"Starting NAT discovery process for {0} to Map-Server {1}"
                                ", requesting NAT info and Map-Notify".format(self.prefix, ms_data.map_server))
                    want_map_notify = True
                    want_nat_discovery = True
                elif now - ms_data.last_notify > 300:
                    # Map-Notify was a long time ago, try to get one
                    logger.info(u"We would like a Map-Notify for {0} from {1}"
                                ", requesting one".format(self.prefix, ms_data.map_server))
                    want_map_notify = True
                    want_nat_discovery = False
                else:
                    if now - ms_data.last_sent < 60:
                        # We sent one in the last minute, don't resend right now
                        continue
                    else:
                        logger.info(u"Sending a Map-Register for {0} to {1}".format(self.prefix, ms_data.map_server))
                        want_map_notify = False
                        want_nat_discovery = False

                # Remember the nonce
                nonce = os.urandom(8)
                ms_data.last_nonce = nonce

                # NATT?
                if want_nat_discovery:
                    # Send an Info-Request
                    message = InfoMessage(nonce=nonce,
                                          key_id=ms_data.key_id,
                                          ttl=1440,
                                          eid_prefix=self.prefix)
                    message.insert_authentication_data(ms_data.key)

                    send_message(message=message,
                                 my_sockets=control_plane_sockets,
                                 destinations=[ms_data.map_server],
                                 port=4342)

                # Build the map-register message
                if not record:
                    locators = self.get_locators(control_plane_sockets)
                    record = MapRegisterRecord(ttl=1440,
                                               authoritative=True,
                                               eid_prefix=self.prefix,
                                               locator_records=locators)

                message = MapRegisterMessage(proxy_map_reply=ms_data.proxy_map_reply,
                                             want_map_notify=want_map_notify,
                                             nonce=nonce,
                                             key_id=ms_data.key_id,
                                             records=[record])
                message.insert_authentication_data(ms_data.key)

                send_message(message=message,
                             my_sockets=control_plane_sockets,
                             destinations=[ms_data.map_server],
                             port=4342)

                # Remember that we sent one
                ms_data.last_sent = now
