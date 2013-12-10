from ipaddress import IPv4Address, IPv6Address, ip_address
from pylisp.utils.auto_addresses import AutoAddress
import logging
import socket

# Get the logger
logger = logging.getLogger(__name__)


class AutoUDPSocket(object):
    def __init__(self, address, port):
        # Convert to IPv*Address if necessary
        if not isinstance(address, (IPv4Address, IPv6Address)):
            address = ip_address(unicode(address))

        # Store
        self.address = address
        self.port = port
        self.family = isinstance(self.address, IPv4Address) and socket.AF_INET or socket.AF_INET6

        # Bind
        self._sock = None
        self._sock_address = isinstance(self.address, IPv4Address) and IPv4Address(0) or IPv6Address(0)
        self.rebind()

        # Request notifications if we are using an AutoAddress
        if isinstance(self.address, AutoAddress):
            self.address.add_notify_target(self)

    def __repr__(self):
        return u"{0}({1!r}, {2})".format(self.__class__.__name__, self.address, self.port)

    def on_address_change(self, address):
        logger.info("{0!r} received a notification that our address has changed: rebinding".format(self))
        self.rebind()

    def rebind(self):
        # Don't rebind if nothing changed
        if int(self.address) == int(self._sock_address):
            logger.info("Rebinding of {0!r} not necessary, address hasn't changed".format(self))
            return self._sock is not None

        if int(self._sock_address) == 0:
            logger.info("Binding socket to {0} port {1}".format(self.address, self.port))
        elif int(self.address) == 0:
            logger.info("Releasing socket binding to {0} port {1}".format(self._sock_address, self.port))
        else:
            logger.warn("Rebinding socket on port {0} from {1} to {2}".format(self.port, self._sock_address,
                                                                              self.address))

        # Release the existing socket
        if self._sock is not None:
            self._sock.close()
            self._sock = None

        # Store an empty address
        self._sock_address = isinstance(self.address, IPv4Address) and IPv4Address(0) or IPv6Address(0)

        # Only bind when address is not loopback, link-local, wild-card or multicast
        if not (self.address.is_loopback or
                self.address.is_link_local or
                self.address.is_multicast or
                self.address.is_unspecified):
            # Create the socket and bind
            try:
                self._sock = socket.socket(self.family, socket.SOCK_DGRAM, socket.SOL_UDP)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                self._sock.bind((unicode(self.address), self.port))

                # Convert to a real IP address (in case it is an AutoAddress)
                self._sock_address = ip_address(unicode(self.address))

                return True
            except socket.error, e:
                logger.exception('Could not bind socket: {0}'.format(e.message))
                pass
        else:
            logger.error('Trying to bind socket to unacceptable address {0}'.format(unicode(self.address)))

        # Resetting data, just to be sure
        if self._sock is not None:
            self._sock.close()
            self._sock = None

        # Store an empty address
        self._sock_address = isinstance(self.address, IPv4Address) and IPv4Address(0) or IPv6Address(0)

        return False

    def fileno(self):
        if not self._sock:
            return None

        return self._sock.fileno()

    def recvfrom(self, bufsize, flags=0):
        # If we don't have a real socket then return nothing
        if self._sock is None:
            return ('', (self._sock_address, 0))

        try:
            data, address = self._sock.recvfrom(bufsize, flags)
            address = (ip_address(unicode(address[0])), address[1])

            # We have input
            return data, address
        except socket.error:
            # On exception return an empty response
            return ('', (self._sock_address, 0))

    def sendto(self, data, flags, address=None):
        # Handle when only two parameters are provided
        if address is None:
            address = flags
            flags = 0

        # Check if we have a real socket
        if self._sock is None:
            return 0

        address = (unicode(address[0]), address[1])

        return self._sock.sendto(data, flags, address)

    def getsockname(self):
        return self._sock_address, 0
