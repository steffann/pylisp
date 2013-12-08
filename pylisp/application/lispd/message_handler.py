'''
Created on 15 jan. 2013

@author: sander
'''

from pylisp.application.lispd.address_tree.ddt_referral_node import handle_ddt_map_request
from pylisp.application.lispd.address_tree.etr_node import ETRNode
from pylisp.application.lispd.utils.prefix import determine_instance_id_and_afi, resolve, resolve_path
from pylisp.packet.lisp.control import EncapsulatedControlMessage, MapNotifyMessage, MapReferralMessage, \
    MapRegisterMessage, MapReplyMessage, MapRequestMessage
from pylisp.packet.lisp.control.info_message import InfoMessage
import logging
from pylisp.packet.lisp.control.map_register_record import MapRegisterRecord
from pylisp.application.lispd.address_tree.map_server_node import MapServerNode


# Get the logger
logger = logging.getLogger(__name__)


def handle_message(received_message, control_plane_sockets, data_plane_sockets):
    """
    Handle a LISP message. The default handle method determines the type
    of message and delegates it to the more specific method
    """
    logger.debug(u"Handling message #{0} ({1}) from {2}".format(received_message.message_nr,
                                                                received_message.message.__class__.__name__,
                                                                received_message.source[0]))

    try:
        if isinstance(received_message.message, MapRequestMessage):
            # A map-request message
            handle_map_request(received_message, control_plane_sockets, data_plane_sockets)

        elif isinstance(received_message.message, MapReplyMessage):
            # A map-reply message
            handle_map_reply(received_message, control_plane_sockets, data_plane_sockets)

        elif isinstance(received_message.message, MapNotifyMessage):
            # A map-notify message (subclass of MapRegisterMessage, so put above it!)
            handle_map_notify(received_message, control_plane_sockets, data_plane_sockets)

        elif isinstance(received_message.message, MapRegisterMessage):
            # A map-register message
            handle_map_register(received_message, control_plane_sockets, data_plane_sockets)

        elif isinstance(received_message.message, MapReferralMessage):
            # A map-referral message
            handle_map_referral(received_message, control_plane_sockets, data_plane_sockets)

        elif isinstance(received_message.message, EncapsulatedControlMessage):
            # Determine the type of ECM
            if isinstance(received_message.inner_message, MapRequestMessage):
                if received_message.message.ddt_originated:
                    # A DDT map-request message
                    handle_ddt_map_request(received_message, control_plane_sockets, data_plane_sockets)
                else:
                    # An encapsulated map-request message
                    handle_enc_map_request(received_message, control_plane_sockets, data_plane_sockets)
            else:
                logger.warning("ECM does not contain a map-request in message %d", received_message.message_nr)
        elif isinstance(received_message.message, InfoMessage):
            handle_info_message(received_message, control_plane_sockets, data_plane_sockets)
        else:
            logger.warning("Unknown content in message %d", received_message.message_nr)
    except:
        logger.exception("Unexpected exception while handling message %d", received_message.message_nr)


def handle_map_reply(received_message, control_plane_sockets, data_plane_sockets):
    pass


def handle_map_register(received_message, control_plane_sockets, data_plane_sockets):
    map_register = received_message.message
    assert isinstance(map_register, MapRegisterMessage)

    for record in map_register.records:
        assert isinstance(record, MapRegisterRecord)

        # Look up the address in the tree
        instance_id, afi, prefix = determine_instance_id_and_afi(record.eid_prefix)
        tree_node = resolve(instance_id, afi, prefix)

        if isinstance(tree_node, MapServerNode):
            tree_node.handle_map_register_record(received_message, record, control_plane_sockets, data_plane_sockets)
        else:
            logger.warn(u"Received a Map-Register message for {0}"
                         ", but we not a MapServer for that EID space".format(prefix))


def handle_map_referral(received_message, control_plane_sockets, data_plane_sockets):
    pass


def handle_map_notify(received_message, control_plane_sockets, data_plane_sockets):
    map_notify = received_message.message
    assert isinstance(map_notify, MapNotifyMessage)

    for record in map_notify.records:
        assert isinstance(record, MapRegisterRecord)

        # Look up the address in the tree
        instance_id, afi, prefix = determine_instance_id_and_afi(record.eid_prefix)
        tree_node = resolve(instance_id, afi, prefix)

        if isinstance(tree_node, ETRNode):
            tree_node.handle_map_notify_record(received_message, record, control_plane_sockets, data_plane_sockets)
        else:
            logger.warn(u"Received a Map-Notify message for {0}"
                         ", but we not a MapServerClient for that EID space".format(prefix))


def handle_info_message(received_message, control_plane_sockets, data_plane_sockets):
    info_message = received_message.message
    assert isinstance(info_message, InfoMessage)

    logger.debug('HANDLING {0!r}'.format(received_message))

    if not received_message.message.is_reply:
        logger.error(u"We are not an RTR, we can only handle InfoMessage replies")
        return

    eid_prefix = info_message.eid_prefix
    instance_id, afi, eid_prefix = determine_instance_id_and_afi(eid_prefix)
    node = resolve(instance_id, afi, eid_prefix)
    if not isinstance(node, ETRNode):
        # Not for us: drop
        logger.warn(u"Ignoring message {0}: Info-Message for prefix {1} in instance {2} "
                    "for which we are not an ETR".format(received_message.message_nr, eid_prefix, instance_id))
        return

    node.handle_info_message_reply(received_message, control_plane_sockets, data_plane_sockets)


def handle_map_request(received_message, control_plane_sockets, data_plane_sockets):
    map_request = received_message.message
    assert isinstance(map_request, MapRequestMessage)

    if len(map_request.eid_prefixes) != 1:
        logger.warn(u"Ignoring message {0}: Map-Request with eid-prefix count != 1".format(received_message.message_nr))
        return

    eid_prefix = map_request.eid_prefixes[0]
    instance_id, afi, eid_prefix = determine_instance_id_and_afi(eid_prefix)
    nodes = resolve_path(instance_id, afi, eid_prefix)
    if not nodes:
        logger.warn(u"Ignoring message {0}: Map-Request for unknown"
                    " instance {1} with AFI {2}".format(received_message.message_nr, instance_id, afi))
        return

    if not isinstance(nodes[0], ETRNode):
        # Not for us: drop
        logger.warn(u"Ignoring message {0}: Map-Request for prefix {1} in instance {2} "
                    "for which we are not an ETR".format(received_message.message_nr, eid_prefix, instance_id))
        return

    nodes[0].handle_map_request(received_message, eid_prefix, control_plane_sockets, data_plane_sockets)


def handle_enc_map_request(received_message, control_plane_sockets, data_plane_sockets):
    pass
