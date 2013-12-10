'''
Created on 1 jun. 2013

@author: sander
'''
from ipaddress import IPv4Address, IPv6Address, IPv4Network
from pylisp.application.lispd.address_tree.base import AbstractNode
from pylisp.application.lispd.received_message import ReceivedMessage
from pylisp.application.lispd.utils.prefix import determine_instance_id_and_afi
from pylisp.packet.lisp.control.locator_record import LocatorRecord
from pylisp.packet.lisp.control.map_register import MapRegisterMessage
from pylisp.packet.lisp.control.map_register_record import MapRegisterRecord
from pylisp.utils.auto_addresses import AutoIPv4Address
from pylisp.utils.auto_socket import AutoUDPSocket
import logging
import threading
import time
import weakref


# Get the logger
logger = logging.getLogger(__name__)


class MapServerException(Exception):
    pass


class MapServerAuthenticationError(MapServerException):
    pass


class MapServerScopeError(MapServerException):
    pass


class MapServerRegistration(object):
    def __init__(self, record, proxy_map_reply=False, timeout=180):
        # Config data
        self.record = record
        self.proxy_map_reply = bool(proxy_map_reply)
        self.timeout = timeout
        self.deadline = time.time() + self.timeout

    def __repr__(self):
        return u"MapServerRegistration({0!r})".format(self.__dict__)


class MSCleanupThread(threading.Thread):
    def __init__(self, ms_node):
        assert isinstance(ms_node, MapServerNode)

        super(MSCleanupThread, self).__init__()

        # Thread properties
        self.name = 'MS-{0}-cleanup'.format(ms_node.prefix)
        self.daemon = True

        # We need our own logger. The global one might disappear on shutdown
        self.logger = logging.getLogger(__name__)

        # Store our state
        self.ms_node = weakref.proxy(ms_node)

        # Shutdown flag
        self._stop_event = threading.Event()

    def run(self):
        try:
            while True:
                try:
                    # Check if we need to stop
                    if self._stop_event.is_set():
                        return

                    # Store current time
                    now = time.time()

                    self.logger.debug('{name} running cleanup'.format(name=self.name))

                    with self.ms_node.registrations_lock:
                        prefixes = self.ms_node.registrations.keys()
                        for prefix in prefixes:
                            sources = self.ms_node.registrations[prefix].keys()
                            for source in sources:
                                # Delete expired registrations
                                if now > self.ms_node.registrations[prefix][source].deadline:
                                    self.logger.info('MapServerRegistration from {source} for {prefix} has expired'.format(source=source,
                                                                                                                           prefix=prefix))
                                    del self.ms_node.registrations[prefix][source]

                            # Remove empty dicts
                            if len(self.ms_node.registrations[prefix]) == 0:
                                del self.ms_node.registrations[prefix]

                except:
                    self.logger.exception("MSCleanupThread {0} caught an unexpected exception: trying again in a bit".format(self.name))

                # Sleep a bit, but watch the stop event
                self._stop_event.wait(30.0)

        except weakref.ReferenceError:
            self.logger.info("MSCleanupThread {0} does not have an MapServerNode anymore: stopping".format(self.name))

    def stop(self):
        self.logger.debug("MSCleanupThread {0} asked to stop".format(self.name))
        self._stop_event.set()


class MapServerNode(AbstractNode):
    def __init__(self, prefix, key, allow_more_specifics=True):
        super(MapServerNode, self).__init__(prefix)
        self.key = key
        self.allow_more_specifics = allow_more_specifics

        # Our store for all registrations
        self.registrations = {}
        self.registrations_lock = threading.RLock()

        # Start a cleanup-thread
        self._cleanup_thread = MSCleanupThread(self)
        self._cleanup_thread.start()

    def __del__(self):
        if self._cleanup_thread:
            self._cleanup_thread.stop()
            self._cleanup_thread = None

    def handle_map_register_record(self, received_message, record, control_plane_sockets, data_plane_sockets):
        assert isinstance(received_message, ReceivedMessage)
        assert isinstance(record, MapRegisterRecord)

        map_register = received_message.message
        assert isinstance(map_register, MapRegisterMessage)

        # Before we go any further we check the authentication data
        if not map_register.verify_authentication_data(self.key):
            raise MapServerAuthenticationError(u"Ignoring a MapRegister message for {0} "
                                               "with invalid authentication data".format(record.eid_prefix))

        # Extract the prefix info
        dummy, dummy, prefix = determine_instance_id_and_afi(record.eid_prefix)

        # Check for invalid prefixes
        if not prefix.overlaps(self.prefix) \
        or prefix.prefixlen < self.prefix.prefixlen:
            raise MapServerScopeError(u"MapRegister message received by Map-Server {0} for prefix {1}".format(self.prefix, prefix))

        # Check for more-specifics
        if prefix.prefixlen > self.prefix.prefixlen \
        and not self.allow_more_specifics:
            raise MapServerScopeError(u'ETR tried to register more-specific {0} in {1}'.format(prefix, self.prefix))

        # Determine canonical source
        if map_register.xtr_id:
            source = '{site_id:x}-{xtr_id:x}'.format(site_id=map_register.site_id,
                                                 xtr_id=map_register.xtr_id)
        else:
            source = received_message.source[0]

        # Store the data for now
        with self.registrations_lock:
            if prefix not in self.registrations:
                self.registrations[prefix] = {}

            # Store registration
            locators = ', '.join(map(lambda locator: unicode(locator.address), record.locator_records))
            if source not in self.registrations[prefix]:
                logger.info('New MapServerRegistration from {source} for {prefix}: {locators}'.format(source=source, prefix=prefix,
                                                                                                      locators=locators))
            else:
                logger.debug('Updating MapServerRegistration from {source} for {prefix}: {locators}'.format(source=source, prefix=prefix,
                                                                                                      locators=locators))

            self.registrations[prefix][source] = MapServerRegistration(proxy_map_reply=map_register.proxy_map_reply,
                                                                       record=record)

    def handle_map_request(self, received_message, control_plane_sockets, data_plane_sockets):
        pass


x = ReceivedMessage(socket=AutoUDPSocket(AutoIPv4Address('vlan2'), 4342),
                    destination=(AutoIPv4Address('vlan2'), 4342),
                    source=(IPv4Address(u'95.97.83.93'), 4342),
                    message_nr=2,
                    message=MapRegisterMessage(nonce='\xa06k\xf3\xf9v\xf9;',
                                               for_rtr=False,
                                               proxy_map_reply=False,
                                               authentication_data='{\x86\xca>\x1a\x10\xbd\xdb\xa3\xe2m\x01\x8b\x84\xe9%B~\xb5l',
                                               xtr_id=266545332235412465937187393052518930680L,
                                               site_id=0L,
                                               records=[MapRegisterRecord(locator_records=[LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=50, weight=100,
                                                                                                         address=IPv4Address(u'87.1.1.77'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True),
                                                                                           LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=10, weight=100,
                                                                                                         address=IPv4Address(u'95.9.3.93'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True),
                                                                                           LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=50, weight=100,
                                                                                                         address=IPv6Address(u'2001:9::1'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True)],
                                                                          authoritative=True,
                                                                          eid_prefix=IPv4Network(u'37.77.57.56/30'),
                                                                          ttl=1440,
                                                                          action=0,
                                                                          map_version=0),
                                                        MapRegisterRecord(locator_records=[LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=50, weight=100,
                                                                                                         address=IPv4Address(u'87.1.1.77'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True),
                                                                                           LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=10, weight=100,
                                                                                                         address=IPv4Address(u'95.9.3.93'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True),
                                                                                           LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=50, weight=100,
                                                                                                         address=IPv6Address(u'2001:9::1'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True)],
                                                                          authoritative=True,
                                                                          eid_prefix=IPv4Network(u'37.77.56.64/26'),
                                                                          ttl=1440,
                                                                          action=0,
                                                                          map_version=0),
                                                        MapRegisterRecord(locator_records=[LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=50, weight=100,
                                                                                                         address=IPv4Address(u'87.1.1.77'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True),
                                                                                           LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=10, weight=100,
                                                                                                         address=IPv4Address(u'95.9.3.93'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True),
                                                                                           LocatorRecord(m_priority=255, m_weight=0,
                                                                                                         priority=50, weight=100,
                                                                                                         address=IPv6Address(u'2001:9::1'),
                                                                                                         reachable=True,
                                                                                                         probed_locator=False,
                                                                                                         local=True)],
                                                                          authoritative=True,
                                                                          eid_prefix=IPv4Network(u'37.77.56.32/31'),
                                                                          ttl=1440,
                                                                          action=0,
                                                                          map_version=0)],
                                               want_map_notify=True,
                                               key_id=1))
