'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import ip_address
from pylisp.application.lispd import settings
from pylisp.application.lispd.address_tree.base import AbstractNode
from pylisp.application.lispd.map_server_registration import MapServerRegistration
from pylisp.application.lispd.send_message import send_message
from pylisp.packet.ip.ipv4 import IPv4Packet
from pylisp.packet.ip.ipv6.base import IPv6Packet
from pylisp.packet.ip.udp import UDPMessage
from pylisp.packet.lisp.control.encapsulated_control_message import EncapsulatedControlMessage
from pylisp.packet.lisp.control.info_message import InfoMessage
from pylisp.packet.lisp.control.locator_record import LocatorRecord
from pylisp.packet.lisp.control.map_notify import MapNotifyMessage
from pylisp.packet.lisp.control.map_register import MapRegisterMessage
from pylisp.packet.lisp.control.map_register_record import MapRegisterRecord
from pylisp.packet.lisp.control.map_reply import MapReplyMessage
from pylisp.packet.lisp.control.map_reply_record import MapReplyRecord
from pylisp.packet.lisp.control.map_request import MapRequestMessage
from pylisp.utils.lcaf.nat_traversal_address import LCAFNATTraversalAddress
import logging
import os
import random
import threading
import time
import weakref


# Design notes:
# - Each Map-Server gets its own thread
# - An InfoRequest is sent from the thread and an object is created to remember this
# - If the main thread received a reply it looks up the corresponding object, stores the reply in it and triggers an event on it
# - The thread waits for this event, with a timeout in case the Map-Server doesn't support InfoRequests
# - The thread then sends a MapRegister, optionally with the WantNotify flag set
# - If the WantNotify flag is set an object is created to remember this
# - If the main thread received a MapNotify it looks up the corresponding object, stores the reply in it and triggers an event on it
# - If the thread set the WantNotify flag it waits for that event, with a timeout in case something goes wrong
# - If there is a timeout the thread tries another MapRegister with the WantNotify flag set
# - On multiple failures the thread goes back to sending the InfoRequest
# - The thread also has a triggerable event in case one of the Locators changes
# - The MapRegister messages are sent every minute, or when the locator-changed event is triggered
# - Do we want to restart the InfoRequest stuff on a locator change?


# Get the logger
logger = logging.getLogger(__name__)


class InfoRequest(object):
    def __init__(self, eid_prefix, msr, control_plane_sockets):
        # Store input
        self.eid_prefix = eid_prefix
        self.msr = msr
        self.control_plane_sockets = control_plane_sockets

        # Create the InfoRequest
        self.info_request = InfoMessage(nonce=os.urandom(8),
                                        key_id=self.msr.key_id,
                                        ttl=1440,
                                        eid_prefix=self.eid_prefix)
        self.info_request.insert_authentication_data(self.msr.key)

        # Remember source and destination of the outgoing request
        self.sent_from = None
        self.sent_to = None

        # Here the reply will be stored
        self.info_reply = None

        # This event will be triggered when the reply is received
        self.reply_received = threading.Event()

    def send(self):
        self.sent_from, self.sent_to = send_message(message=self.info_request,
                                                    my_sockets=self.control_plane_sockets,
                                                    destinations=[self.msr.map_server],
                                                    port=4342)

    def set_reply_if_matches(self, source, info_message):
        if source != self.msr.map_server \
        or info_message.nonce != self.info_request.nonce:
            # Not for us
            return False

        logger.debug(u"Received a reply to InfoRequest from {0}".format(source))
        self.info_reply = info_message
        self.info_reply.reply.private_etr_rloc = self.sent_from[0]
        self.reply_received.set()
        return True


class MapRegister(object):
    def __init__(self, prefix, msr, locators, nat_info, control_plane_sockets, data_plane_sockets, want_map_notify=False):
        assert isinstance(msr, MapServerRegistration)

        # Extract RTRs
        rtrs = nat_info and nat_info.rtr_rlocs or set()

        # Store input
        self.prefix = prefix
        self.msr = msr
        self.nat_info = nat_info
        self.control_plane_sockets = control_plane_sockets
        self.data_plane_sockets = data_plane_sockets
        self.want_map_notify = want_map_notify or bool(rtrs)

        # Generate the map-register
        self.map_register = MapRegisterMessage(proxy_map_reply=self.msr.proxy_map_reply,
                                               for_rtr=bool(rtrs),
                                               want_map_notify=self.want_map_notify,
                                               nonce=os.urandom(8),
                                               key_id=self.msr.key_id,
                                               records=[MapRegisterRecord(ttl=1440,
                                                                          authoritative=True,
                                                                          eid_prefix=self.prefix,
                                                                          locator_records=locators)],
                                               xtr_id=settings.config.XTR_ID,
                                               site_id=settings.config.SITE_ID)
        self.map_register.insert_authentication_data(self.msr.key)

        # Remember source and destination of the outgoing register
        self.sent_from = None
        self.sent_to = None

        # Here the notify is stored
        self.notify = None

        # This event will be triggered when the notify is received
        self.notify_received = threading.Event()

    def send(self):
        if not self.nat_info:
            # Plain Map_Register
            logger.debug(u"Sending Map-Register for {0} to Map-Server {1}".format(self.prefix, self.msr.map_server))
            self.sent_from, self.sent_to = send_message(message=self.map_register,
                                                        my_sockets=self.control_plane_sockets,
                                                        destinations=[self.msr.map_server],
                                                        port=4342)
        else:
            logger.debug(u"Sending NATT Map-Register for {0} to Map-Server {1}".format(self.prefix, self.msr.map_server))

            # Create an IP packet
            if self.msr.map_server.version != self.nat_info.private_etr_rloc.version:
                logger.error("Address family mismatch between local RLOC and Map-Server")
                return

            if self.msr.map_server.version == 4:
                ip_packet = IPv4Packet()
            else:
                ip_packet = IPv6Packet()

            # Fill the packet
            ip_packet.ttl = 63
            ip_packet.source = self.nat_info.private_etr_rloc
            ip_packet.destination = self.msr.map_server

            # UDP payload
            inner_udp = UDPMessage(source_port=4342,
                                   destination_port=4342,
                                   payload=self.map_register)
            inner_udp.checksum = inner_udp.calculate_checksum(source=ip_packet.source,
                                                              destination=ip_packet.destination)

            # Put UDP in the packet
            ip_packet.next_header = inner_udp.header_type
            ip_packet.payload = inner_udp

            # Encapsulate it in an ECM
            ecm = EncapsulatedControlMessage(payload=ip_packet)

            send_message(message=ecm,
                         my_sockets=self.data_plane_sockets,
                         destinations=self.nat_info.rtr_rlocs,
                         port=4342)

    def set_notify_if_matches(self, source, notify):
        assert isinstance(notify, MapNotifyMessage)

        if source != self.msr.map_server \
        or notify.nonce != self.map_register.nonce:
            # Not for us
            return False

        logger.debug(u"Received a MapNotify from {0}".format(source))
        self.notify = notify
        self.notify_received.set()
        return True

    def notify_content_ok(self):
        if not self.notify_received.is_set():
            logger.error("Cannot validate a MapNotify message without actually receiving it")
            return False

        if not self.notify.verify_authentication_data(self.msr.key):
            logger.debug(u"MapNotify authentication data is not valid")
            return False

        if self.notify.nonce != self.map_register.nonce:
            logger.debug(u"MapNotify nonce {0x} != MapRegister {1x}".format(self.notify.nonce,
                                                                           self.map_register.nonce))
            return False

        if self.notify.key_id != self.map_register.key_id:
            logger.debug(u"MapNotify key-id {0} != MapRegister {1}".format(self.notify.key_id,
                                                                          self.map_register.key_id))
            return False

        if self.notify.xtr_id != 0 and self.notify.xtr_id != self.map_register.xtr_id:
            logger.debug(u"MapNotify XTR-id {0x} != MapRegister {1x}".format(self.notify.xtr_id,
                                                                            self.map_register.xtr_id))
            return False

        if self.notify.site_id != 0 and self.notify.site_id != self.map_register.site_id:
            logger.debug(u"MapNotify Site-id {0x} != MapRegister {1x}".format(self.notify.site_id,
                                                                             self.map_register.site_id))
            return False

        # Validate records
        if len(self.notify.records) != len(self.map_register.records):
            logger.debug(u"MapNotify contains {0} records != MapRegister {1}".format(len(self.notify.records),
                                                                                    len(self.map_register.records)))
            return False

        for reg_record in self.map_register.records:
            assert isinstance(reg_record, MapRegisterRecord)

            record_found = False
            for record in self.notify.records:
                assert isinstance(record, MapRegisterRecord)

                if record.eid_prefix != reg_record.eid_prefix \
                or record.ttl != reg_record.ttl \
                or record.action != reg_record.action \
                or record.map_version != reg_record.map_version \
                or len(record.locator_records) != len(reg_record.locator_records):
                    # No match
                    continue

                for reg_locator in reg_record.locator_records:
                    assert isinstance(reg_locator, LocatorRecord)

                    locator_found = False
                    for locator in record.locator_records:
                        assert isinstance(locator, LocatorRecord)

                        if locator.priority == reg_locator.priority \
                        and locator.weight == reg_locator.weight \
                        and locator.m_priority == reg_locator.m_priority \
                        and locator.m_weight == reg_locator.m_weight \
                        and locator.reachable == reg_locator.reachable \
                        and locator.address == reg_locator.address:
                            locator_found = True
                            break

                    if not locator_found:
                        logger.debug("Locators for {0} do not match".format(record.eid_prefix))

                # That seemed ok
                record_found = True
                break

            if not record_found:
                logger.debug(u"MapNotify does not contain record for {0} from MapRegister".format(reg_record.eid_prefix))
                return False

        logger.debug(u"MapNotify validated")
        return True


class MSRThread(threading.Thread):
    def __init__(self, etrnode, msr):
        assert(isinstance(etrnode, ETRNode))
        assert(isinstance(msr, MapServerRegistration))

        super(MSRThread, self).__init__()

        self.etrnode = weakref.proxy(etrnode)
        self.msr = msr

        self.need_new_registration = False

        self.name = '{0}-{1}'.format(etrnode.prefix, msr.map_server)
        self.daemon = True

        self._stop_event = threading.Event()

    def get_nat_info(self):
        # Check if we are forced off
        if self.msr.use_rtr is False:
            logger.debug(u"MSRThread {0} had RTR usage disabled".format(self.name))
            return None

        # Start with sending out an InfoRequest
        info_req = InfoRequest(self.etrnode.prefix, self.msr, self.etrnode.control_plane_sockets)
        self.etrnode.outstanding_info_requests.append(info_req)

        for remaining_attempts in [2, 1, 0]:
            # Send it
            info_req.send()

            # Wait for the reply for 1 second
            info_req.reply_received.wait(1.0)

            if self._stop_event.is_set():
                return

            if info_req.reply_received.is_set():
                break

            if remaining_attempts > 0:
                logger.info("MSRThread {0} didn't receive answer to InfoRequest, retrying...".format(self.name))

        # Clean up
        self.etrnode.outstanding_info_requests.remove(info_req)

        if not info_req.reply_received.is_set():
            logger.error("MapServer {0} doesn't answer to InfoRequests for prefix {1}"
                         ", assuming no NAT".format(self.msr.map_server,
                                                    self.etrnode.prefix))
            reply = None
            behind_nat = False
        else:
            reply = info_req.info_reply.reply
            behind_nat = (reply.global_etr_rloc != reply.private_etr_rloc or
                          reply.etr_port != 4342)

        if not behind_nat:
            logger.info("No NAT detected between us at {0} and MapServer {1}".format(info_req.sent_from[0],
                                                                                     info_req.sent_to[0]))
            if self.msr.use_rtr is True:
                if reply:
                    logger.info("Forcing use of RTR, even though no NAT is detected")
                    behind_nat = True
                else:
                    logger.error("Cannot force use of RTR, no answer to InfoRequest received")

        else:
            logger.info("NAT between us at {0} and MapServer {1} (it sees {2})".format(reply.private_etr_rloc,
                                                                                       reply.map_server_rloc,
                                                                                       reply.global_etr_rloc))

        if not behind_nat:
            return None
        else:
            return reply

    def register(self, nat_info, force_map_notify=False):
        # Determine the locators
        my_rtrs = nat_info and nat_info.rtr_rlocs or []
        locators = self.etrnode.get_etr_locators(local_sockets=self.etrnode.control_plane_sockets,
                                                 tentative_rtrs=my_rtrs)

        # Create the MapRegister
        map_reg = MapRegister(prefix=self.etrnode.prefix,
                              msr=self.msr,
                              locators=locators,
                              nat_info=nat_info,
                              control_plane_sockets=self.etrnode.control_plane_sockets,
                              data_plane_sockets=self.etrnode.data_plane_sockets,
                              want_map_notify=force_map_notify or (random.randint(0, 10) == 0))

        if not map_reg.want_map_notify:
            # Fire and forget
            map_reg.send()
            return True

        # Store it as outstanding
        self.etrnode.outstanding_map_registrations.append(map_reg)

        for remaining_attempts in [2, 1, 0]:
            # Send it
            map_reg.send()

            # Wait for the reply for 1 second
            map_reg.notify_received.wait(1.0)

            if self._stop_event.is_set():
                return

            if map_reg.notify_received.is_set():
                break

            if remaining_attempts > 0:
                logger.info("MSRThread {0} didn't receive MapNotify for MapRegister, retrying...".format(self.name))

        # Clean up
        self.etrnode.outstanding_map_registrations.remove(map_reg)

        if map_reg.notify_received.is_set():
            # Check the content
            if not map_reg.notify_content_ok():
                logger.error("The received MapNotify content does not match the MapRegister we sent")
                return False

            # All good
            return True

        # Bad!
        logger.error("MapServer {0} doesn't answer to MapNotify requests for prefix {1}".format(self.msr.map_server,
                                                                                                self.etrnode.prefix))
        return False

    def run(self):
        last_nat_info = 0
        last_registration = 0
        last_registration_was_ok = False
        try:
            while True:
                # Check if we need to stop
                if self._stop_event.is_set():
                    return

                # Do we need to refresh our NAT detection
                now = time.time()

                if not last_registration_was_ok \
                or last_nat_info + (15 * 60) < now:
                    # See if we are going to use RTRs
                    nat_info = self.get_nat_info()
                    last_nat_info = now

                    # Force a Map-Notify by pretending the last registration was not ok
                    last_registration_was_ok = False

                if not last_registration_was_ok \
                or self.need_new_registration \
                or last_registration + 60 < now:
                    # Reset the flag first to prevent race conditions
                    self.need_new_registration = False

                    # Register in the Map-Server
                    last_registration_was_ok = self.register(nat_info=nat_info,
                                                             force_map_notify=not last_registration_was_ok)
                    last_registration = now

                    if nat_info:
                        # Let the other parts of the code know we have registered through NAT
                        self.etrnode.set_rtrs(self.msr, nat_info.rtr_rlocs)
                    else:
                        # Clear our RTRs in case we set them previously
                        self.etrnode.set_rtrs(self.msr, [])

                # Sleep a bit, but watch the stop event
                self._stop_event.wait(5.0)

        except weakref.ReferenceError:
            logging.info("MSRThread {0} does not have an ETRNode anymore: stopping".format(self.name))

    def stop(self):
        logging.debug("MSRThread {0} asked to stop".format(self.name))
        self._stop_event.set()


class ETRNode(AbstractNode):
    def __init__(self, prefix, locators=None, map_servers=None):
        super(ETRNode, self).__init__(prefix)

        self._locators = set()

        # Dictionaries with an MapServerRegistration as key
        self._msr_threads = {}
        self._rtrs = {}

        self.outstanding_info_requests = []
        self.outstanding_map_registrations = []

        locators = locators or []
        for locator in locators:
            self.add_locator(locator)

        map_servers = map_servers or []
        for msr in map_servers:
            self.add_map_server_registration(msr)

    def __del__(self):
        for msr_thread in self._msr_threads.values():
            msr_thread.stop()

    def set_sockets(self, control_plane_sockets, data_plane_sockets):
        super(ETRNode, self).set_sockets(control_plane_sockets, data_plane_sockets)

        if self.control_plane_sockets:
            # Make sure the MSR threads are started
            for msr_thread in self._msr_threads.values():
                if not msr_thread.is_alive():
                    msr_thread.start()

    def add_locator(self, locator):
        # Don't add duplicates
        if locator in self._locators:
            logger.debug("Not adding the same Locator {0!r} twice".format(locator))
            return

        if not isinstance(locator, LocatorRecord):
            raise ValueError(u"Locator must be instance of LocatorRecord")

        self._locators.add(locator)
        locator.add_notify_target(self)

    def remove_locator(self, locator):
        locator.remove_notify_target(self)
        self._locators.discard(locator)

    def on_locator_change(self, locator):
        self._signal_locator_change()

    def _locators_have_changed(self):
        # Signal the threads that new registration is required
        logger.debug("Locators have changed, telling all threads to send new registration")
        for msr_thread in self._msr_threads.values():
            msr_thread.need_new_registration = True

    def add_map_server_registration(self, msr):
        # Don't add duplicate MSRs
        if msr in self._msr_threads:
            logger.debug("Not adding the same MSR {0!r} twice".format(msr))
            return

        msr_thread = MSRThread(self, msr)
        if self.control_plane_sockets:
            msr_thread.start()
        self._msr_threads[msr] = msr_thread

    def remove_map_server_registration(self, msr):
        msr_thread = self._msr_threads.get(msr)
        if not msr_thread:
            logger.warning(u"{0!r} MapServerRegistration {1!r} not found".format(self, msr))
            return

        logger.debug(u"{0!r} stopping {1!r}".format(self, msr))
        msr_thread.stop()
        del self._msr_threads[msr]

    def set_rtrs(self, msr, rtrs):
        old_rtrs = self._rtrs.get(msr, [])
        self._rtrs[msr] = set(rtrs)

        # Signal a locator change when the RTRs change
        if old_rtrs != self._rtrs[msr]:
            self._locators_have_changed()

    def get_rtrs(self):
        rtrs = set()
        for rtr_set in self._rtrs.values():
            for rtr in rtr_set:
                # Create new addresses to make sure we don't have any fancy sub-classes like AutoAddresses
                rtrs.add(ip_address(unicode(rtr)))

        return rtrs

    def get_etr_locators(self, local_sockets, tentative_rtrs=[]):
        # Collect the RTRs
        rtrs = self.get_rtrs() | set(tentative_rtrs)

        # Copy locators and adjust
        locators = set()
        rtrs_already_included = False
        for locator in self._locators:
            # Skip unbound locators
            if int(locator.address) == 0:
                continue

            # Determine if this locator is local by comparing locator's address to our own socket addresses
            local = False
            for sock in local_sockets:
                if int(sock.address) == int(locator.address):
                    local = True
                    break

            if local and rtrs:
                if not rtrs_already_included:
                    # Replace our local locator with the RTRs
                    for rtr in rtrs:
                        locators.add(LocatorRecord(priority=locator.priority,
                                                   weight=locator.weight,
                                                   m_priority=locator.m_priority,
                                                   m_weight=locator.m_weight,
                                                   local=False,
                                                   reachable=True,
                                                   address=rtr))
                    rtrs_already_included = True
            else:
                # We are not using RTRs, or this is not a local locator
                locators.add(LocatorRecord(priority=locator.priority,
                                           weight=locator.weight,
                                           m_priority=locator.m_priority,
                                           m_weight=locator.m_weight,
                                           local=local,
                                           reachable=True,
                                           address=ip_address(unicode(locator.address))))

        return locators

    def handle_map_notify_record(self, received_message, record, control_plane_sockets, data_plane_sockets):
        map_notify = received_message.message
        assert isinstance(map_notify, MapNotifyMessage)

        for map_reg in self.outstanding_map_registrations:
            if map_reg.set_notify_if_matches(received_message.source[0], map_notify):
                # Found it, return
                return

        logger.warn(u"Received an unexpected Map-Notify for {0} from {1}".format(record.eid_prefix,
                                                                                 received_message.source[0]))

    def handle_map_request(self, received_message, eid_prefix, control_plane_sockets, data_plane_sockets):
        map_request = received_message.message
        assert isinstance(map_request, MapRequestMessage)

        # Return our locators
        locators = self.get_etr_locators(control_plane_sockets)

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
                                          eid_prefix=self.prefix,
                                          locator_records=locators)
        else:
            reply_record = MapReplyRecord(ttl=1440,
                                          action=MapReplyRecord.ACT_NATIVELY_FORWARD,
                                          authoritative=True,
                                          eid_prefix=self.prefix)

        if map_request.probe:
            logger.info(u"Replying to probe for {0} from {1}".format(eid_prefix, received_message.source[0]))

        # Send the reply to the RLOCs in the MapRequest
        reply = MapReplyMessage(probe=map_request.probe,
                                nonce=map_request.nonce,
                                records=[reply_record])

        send_message(message=reply,
                     my_sockets=control_plane_sockets,
                     destinations=map_request.itr_rlocs,
                     port=received_message.source[1])

    def handle_info_message_reply(self, received_message, control_plane_sockets, data_plane_sockets):
        info_message = received_message.message
        assert isinstance(info_message, InfoMessage)
        assert isinstance(info_message.reply, LCAFNATTraversalAddress)

        for info_req in self.outstanding_info_requests:
            if info_req.set_reply_if_matches(received_message.source[0], info_message):
                # Found it, return
                return

        logger.warn(u"Received an unexpected Info-Message reply for {0} from {1}".format(info_message.eid_prefix,
                                                                                         received_message.source[0]))
