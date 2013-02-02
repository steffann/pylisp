'''
Created on 31 jan. 2013

@author: sander
'''
from pylisp.application.lispd.map_server.site import Site
from pylisp.application.lispd.message_handler import MessageHandler
from pylisp.application.lispd.received_message import ReceivedMessage
from pylisp.packet.lisp.control.map_reply_record import MapReplyRecord
from pylisp.utils.IPy_clone import IP, IPSet
import logging
from pylisp.packet.lisp.control.map_register import MapRegisterMessage


# Get the logger
logger = logging.getLogger(__name__)


class MapServerHandler(MessageHandler):
    def __init__(self, sites=None):
        super(MapServerHandler, self).__init__()

        # Store sites
        self.sites = sites or []

        # Sanity check
        self.sanitize()

    def sanitize(self):
        all_site_eids = IPSet()

        # Process sites
        for site in self.sites:
            assert isinstance(site, Site)

            # Process EID prefixes
            for site_eid_prefix in site.eid_prefixes:
                assert isinstance(site_eid_prefix, IP)

                if all_site_eids.overlaps(site_eid_prefix):
                    raise ValueError('Sites have overlapping prefixes')

                all_site_eids.add(site_eid_prefix)

    def _find_site(self, eid_prefix):
        # Process sites
        for site in self.sites:
            assert isinstance(site, Site)

            # Process EID prefixes
            for site_eid_prefix in site.eid_prefixes:
                assert isinstance(site_eid_prefix, IP)

                if eid_prefix in site_eid_prefix:
                    return site

    def handle_map_register(self, received_message, my_sockets):
        assert isinstance(received_message, ReceivedMessage)
        message = received_message.message
        assert isinstance(message, MapRegisterMessage)

        accepted_records = []

        for record in message.records:
            assert isinstance(record, MapReplyRecord)

            site = self._find_site(record.eid_prefix)
            if not site:
                logger.warning("Received Map-Register for unknown prefix %s",
                               record.eid_prefix)
                continue

            # Verify authentication
            key = site.authentication_key
            if not message.verify_authentication_data(key):
                logger.error("Authentication failed for registration of "
                             "prefix %s under site %s", record.eid_prefix,
                             site.name)
                print bytes(message).encode('hex')
                print message.authentication_data.encode('hex')
                print message.calculate_authentication_data(key).encode('hex')
                continue

            logger.info("Accepting registration of prefix %s under site %s",
                        record.eid_prefix, site.name)

        # Handled
        return True
