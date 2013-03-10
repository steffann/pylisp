'''
Created on 31 jan. 2013

@author: sander
'''
from pylisp.application.lispd import settings
from pylisp.application.lispd.map_server.site import Site
from pylisp.application.lispd.message_handler import MessageHandler
from pylisp.application.lispd.received_message import ReceivedMessage
from pylisp.packet.lisp.control import MapRegisterMessage, MapReplyRecord
from pylisp.utils.IPy_clone import IP, IPSet
from threading import Timer
import logging


# Get the logger
logger = logging.getLogger(__name__)


class MapServerHandler(MessageHandler):
    def __init__(self, sites=None):
        super(MapServerHandler, self).__init__()

        # Store aggregates and sites
        self.sites = sites or []

    def start(self):
        # Clean-up thread
        self._cleanup_interval = 60
        self._cleanup_timer = Timer(self._cleanup_interval, self._cleanup)
        self._cleanup_timer.start()

        self._shutting_down = False

    def stop(self):
        logger.debug("Map-Server handler stopping")
        self._shutting_down = True
        self._cleanup_timer.cancel()

    def _cleanup(self):
        # Don't bother if we're shutting down
        if self._shutting_down:
            return

        logger.debug("Running Map-Server cleanup")

        # Clean site data
        for site in self.sites:
            site.clean_registrations()

        # If we didn't get shut down in the mean time...
        if not self._shutting_down:
            # Set next timer
            self._cleanup_timer = Timer(self._cleanup_interval, self._cleanup)
            self._cleanup_timer.start()

    def sanitize(self):
        all_site_eids = IPSet()

        # Process sites
        for site in self.sites:
            assert isinstance(site, Site)

            # Process EID prefixes
            for site_eid_prefix in site.eid_prefixes:
                assert isinstance(site_eid_prefix, IP)

                if site_eid_prefix not in settings.config.authoritative_for:
                    raise ValueError("Cannot add prefix %s, only responsible "
                                     "for %s" % (site_eid_prefix,
                                                 settings.config.authoritative_for))

                if all_site_eids.overlaps(site_eid_prefix):
                    raise ValueError("Sites have overlapping prefixes")

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

        if self._shutting_down:
            logger.warning("Did not handle message %d: already shutting down",
                           received_message.message_nr)
            return False

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
