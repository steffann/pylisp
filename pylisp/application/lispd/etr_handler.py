'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import IPv4Network, IPv4Address, IPv6Network, IPv6Address, ip_address
from pylisp.application.lispd import settings
from pylisp.application.lispd.address_tree import ETRNode
from pylisp.application.lispd.map_server_registration import MapServerRegistration
from pylisp.application.lispd.send_message import send_message
from pylisp.application.lispd.utils.prefix import determine_instance_id_and_afi
from pylisp.packet.lisp.control.map_notify import MapNotifyMessage
from pylisp.packet.lisp.control.map_reply import MapReplyMessage
from pylisp.packet.lisp.control.map_reply_record import MapReplyRecord
from pylisp.packet.lisp.control.map_request import MapRequestMessage
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

    if isinstance(tree_node, ETRNode):
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
                    ", but we not a MapServerClient for that EID space".format(prefix))

    return False


def handle_map_notify(received_message, my_sockets):
    logger.debug("Handling message %d as a Map-Notify", received_message.message_nr)

    map_notify = received_message.message
    for record in map_notify.records:
        update_map_server_client(received_message, record)


def handle_map_request(received_message, my_sockets):
    logger.debug("Handling message %d as a Map-Request for this ETR", received_message.message_nr)

    map_request = received_message.message
    assert isinstance(map_request, MapRequestMessage)

    if len(map_request.eid_prefixes) != 1:
        logger.warn("Ignoring message {0}: Map-Request with eid-prefix count != 1".format(received_message.message_nr))
        return

    eid_prefix = map_request.eid_prefixes[0]
    instance_id, afi, eid_prefix = determine_instance_id_and_afi(eid_prefix)

    # Check instance_id
    if (instance_id not in settings.config.INSTANCES or afi not in settings.config.INSTANCES[instance_id]):
        logger.warn("Ignoring message {0}: Map-Request for unknown"
                    " instance {1} with AFI {2}".format(received_message.message_nr, instance_id, afi))
        return

    # Look up the prefix
    nodes = settings.config.INSTANCES[instance_id][afi].resolve_path(eid_prefix)
    node = nodes[0]
    if not isinstance(node, ETRNode):
        # Not for us: drop
        return

    # Return our locators
    locators = node.get_locators(my_sockets)

    # Do we have locators?
    if locators:
        # Get the address the Map-Request was sent to
        etr_address = ip_address(unicode(received_message.destination[0]))

        # Pretend that all locators are reachable
        # TODO: implement something better
        for locator in locators:
            locator.reachable = True
            locator.probed_locator = map_request.probe and etr_address == locator.address

        reply_record = MapReplyRecord(ttl=1440,
                                      authoritative=True,
                                      eid_prefix=node.prefix,
                                      locator_records=locators)
    else:
        reply_record = MapReplyRecord(ttl=1440,
                                      action=MapReplyRecord.ACT_NATIVELY_FORWARD,
                                      authoritative=True,
                                      eid_prefix=node.prefix)

    if map_request.probe:
        logger.info(u"Replying to probe for {0} from {1}".format(eid_prefix, received_message.source[0]))

    # Send the reply to the RLOCs in the MapRequest
    reply = MapReplyMessage(probe=map_request.probe,
                            nonce=map_request.nonce,
                            records=[reply_record])

    send_message(message=reply,
                 my_sockets=my_sockets,
                 destinations=map_request.itr_rlocs,
                 port=received_message.source[1])
