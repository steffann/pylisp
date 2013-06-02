'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import IPv4Network, IPv4Address, IPv6Network, IPv6Address, ip_address
from pylisp.application.lispd import settings
from pylisp.application.lispd.address_tree.map_server_client_node import MapServerClientNode
from pylisp.application.lispd.map_server_registration import MapServerRegistration
from pylisp.application.lispd.received_message import ReceivedMessage
from pylisp.packet.lisp.control.map_notify import MapNotifyMessage
from pylisp.utils.lcaf.instance_address import LCAFInstanceAddress
import logging
import time


# Get the logger
logger = logging.getLogger(__name__)


def update_map_server_client(received_message, record):
    map_notify = received_message.message
    assert isinstance(map_notify, MapNotifyMessage)

    prefix = record.eid_prefix
    if not isinstance(prefix, LCAFInstanceAddress):
        if not isinstance(prefix, (IPv4Network, IPv4Address, IPv6Network, IPv6Address)):
            raise ValueError(u"Unexpected EID prefix %r in message %d", prefix, received_message.message_nr)
        prefix = LCAFInstanceAddress(instance_id=0, address=prefix)

    # Look up the address in the tree
    instance = settings.config.INSTANCES.get(prefix.instance_id)
    if instance is None:
        logger.warn(u"Received a Map-Notify for unknown instance {0}".format(prefix.instance_id))
        return False

    afi = isinstance(prefix.address, (IPv4Address, IPv4Network)) and 1 or 2
    tree_node = instance[afi].resolve(prefix.address)

    if isinstance(tree_node, MapServerClientNode):
        # Ok, we might actually have sent a MapRegister for this. Try to find a corresponding Map-Server
        source = ip_address(unicode(received_message.source[0]))
        for ms_data in tree_node.map_servers:
            with ms_data.lock:
                assert isinstance(ms_data, MapServerRegistration)
                if source == ms_data.map_server:
                    # Check the nonce and authentication data
                    if map_notify.nonce != ms_data.last_nonce:
                        logger.warn(u"Received a Map-Notify for {0} Map-Server {1}"
                                    " with the wrong nonce".format(prefix, source))
                        return False

                    if not map_notify.verify_authentication_data(ms_data.key):
                        logger.warn(u"Received a Map-Notify for {0} from Map-Server {1}"
                                    " with invalid authentication".format(prefix, source))
                        return False

                    logger.info(u"Received a Map-Notify for {0} from Map-Server {1}".format(prefix, source))
                    ms_data.last_notify = time.time()
                    return True

        logger.warn(u"Received a Map-Notify for {0}"
                    " from unknown Map-Server {1}".format(prefix, source))
    else:
        logger.warn(u"Received a Map-Notify for {0}"
                    ", but we not a MapServerClient for thet EID space".format(prefix))

    return False


def handle_map_notify(received_message, my_sockets):
    assert isinstance(received_message, ReceivedMessage)

    logger.debug("Handling message %d as a Map-Nofity", received_message.message_nr)

    map_notify = received_message.message
    for record in map_notify.records:
        update_map_server_client(received_message, record)
