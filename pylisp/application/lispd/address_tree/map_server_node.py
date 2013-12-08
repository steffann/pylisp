'''
Created on 1 jun. 2013

@author: sander
'''
from pylisp.application.lispd.address_tree.base import AbstractNode
from pylisp.application.lispd.received_message import ReceivedMessage
from pylisp.application.lispd.utils.prefix import determine_instance_id_and_afi
from pylisp.packet.lisp.control.map_register import MapRegisterMessage
from pylisp.packet.lisp.control.map_register_record import MapRegisterRecord
import logging


# Get the logger
logger = logging.getLogger(__name__)


class MapServerNode(AbstractNode):
    def __init__(self, prefix, key, allow_more_specifics=True):
        super(MapServerNode, self).__init__(prefix)
        self.key = key
        self.allow_more_specifics = allow_more_specifics

    def handle_map_register_record(self, received_message, record, control_plane_sockets, data_plane_sockets):
        assert isinstance(received_message, ReceivedMessage)
        assert isinstance(record, MapRegisterRecord)

        map_register = received_message.message
        assert isinstance(map_register, MapRegisterMessage)

        # Before we go any further we check the authentication data
        if not map_register.verify_authentication_data(self.key):
            logger.error(u"Ignoring a MapRegister message for {0} "
                          "with invalid authentication data".format(record.eid_prefix))
            return

        # Extract the prefix info
        dummy, dummy, prefix = determine_instance_id_and_afi(record.eid_prefix)

        # Check for invalid prefixes
        if not prefix.overlaps(self.prefix) \
        or prefix.prefixlen < self.prefix.prefixlen:
            logger.error(u"MapRegister message received by Map-Server {0} for prefix {1}".format(self.prefix, prefix))
            return

        # Check for more-specifics
        if prefix.prefixlen > self.prefix.prefixlen \
        and not self.allow_more_specifics:
            logger.error(u'ETR tried to register more-specific {0} in {1}'.format(prefix, self.prefix))
            return

        # Store the data for now
        if prefix.prefixlen not in self.registrations:
            self.registrations[prefix.prefixlen] = {}

        if received_message.source not in self.registrations[prefix.prefixlen]:
            self.registrations[prefix.prefixlen][received_message.source]
        self.registrations[prefix.prefixlen]

    def handle_map_request(self, received_message, control_plane_sockets, data_plane_sockets):
        pass
