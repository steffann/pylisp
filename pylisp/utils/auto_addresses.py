'''
Created on 4 jun. 2013

@author: sander
'''
from abc import ABCMeta
from ipaddress import IPv4Address, IPv6Address, ip_address
import logging
import netifaces
import socket
import threading


__all__ = ['AutoIPv4Address', 'AutoIPv6Address', 'AutoSocket']


# Get the logger
logger = logging.getLogger(__name__)


class AutoAddress(object):
    __meta__ = ABCMeta

    def __init__(self, if_name):
        # Create lock
        self.lock = threading.RLock()

        # Store the interface name
        self._if_name = if_name

        # Automatically update
        self.update_address()

    def update_address(self):
        with self.lock:
            # Zero address as fall-back
            new_ip = 0

            try:
                # Find the first suitable address
                addresses = netifaces.ifaddresses(self._if_name)[self._address_family]
                for potential_address in addresses:
                    # Get the address out of the dict and strip away any scope-id
                    potential_address = potential_address['addr'].split('%')[0]

                    # Convert to a proper object
                    potential_address = ip_address(unicode(potential_address))

                    # And test it for suitability
                    if not (potential_address.is_link_local or
                            potential_address.is_loopback or
                            potential_address.is_multicast or
                            potential_address.is_reserved or
                            potential_address.is_unspecified):

                        new_ip = int(potential_address)
                        break

            except (ValueError, KeyError):
                # Ignore error: continue without address
                pass

            self._ip = new_ip

    def __hash__(self):
        # The address is mutable, the interface name isn't
        return hash(self._ifname)


class AutoIPv4Address(AutoAddress, IPv4Address):
    """
    Automatically determines the 'first' IPv4 address of an interface and
    provides compatibility with ipaddress.IPv4Address.
    """
    _address_family = netifaces.AF_INET

    def __init__(self, if_name):
        IPv4Address.__init__(self, 0)
        AutoAddress.__init__(self, if_name)


class AutoIPv6Address(AutoAddress, IPv6Address):
    """
    Automatically determines the 'first' IPv6 address of an interface and
    provides compatibility with ipaddress.IPv6Address.
    """
    _address_family = netifaces.AF_INET6

    def __init__(self, if_name):
        IPv6Address.__init__(self, 0)
        AutoAddress.__init__(self, if_name)


class AutoUDPSocket(object):
    def __init__(self, address, port):
        # Convert to IPv*Address if necessary
        if not isinstance(address, (IPv4Address, IPv6Address)):
            address = ip_address(unicode(address))

        # Create lock
        self.lock = threading.RLock()

        # Store
        self.address = address
        self.port = port
        self.family = isinstance(self.address, IPv4Address) and socket.AF_INET or socket.AF_INET6

        # Bind
        self._sock = None
        self._sock_address = isinstance(self.address, IPv4Address) and IPv4Address(0) or IPv6Address(0)
        self.rebind()

    def __repr__(self):
        return u'<AutoUDPSocket {0} {1} {2}>'.format(self.address, self._sock_address, self._sock)

    def rebind(self):
        with self.lock:
            # Try to update the address if possible
            if isinstance(self.address, AutoAddress):
                self.address.update_address()

            # Don't rebind if nothing changed
            if int(self.address) == int(self._sock_address):
                return self._sock is not None

            logger.warn("REBINDING {0} to {1}".format(self._sock_address, self.address))

            # Refuse to bind to loopback, link-local, wild-card or multicast addresses
            if not (self.address.is_loopback or
                    self.address.is_link_local or
                    self.address.is_multicast or
                    self.address.is_unspecified):
                # Create the socket and bind
                try:
                    self._sock = socket.socket(self.family, socket.SOCK_DGRAM, socket.SOL_UDP)
                    self._sock.bind((unicode(self.address), self.port))
                    self._sock_address = ip_address(unicode(self.address))
                    return True
                except socket.error:
                    pass

            self._sock = None
            self._sock_address = isinstance(self.address, IPv4Address) and IPv4Address(0) or IPv6Address(0)
            return False

    def fileno(self):
        if not self._sock:
            return None

        return self._sock.fileno()

    def recvfrom(self, bufsize, flags=0):
        # If we don't have a real socket then return nothing
        if self._sock is None:
            return ('', (isinstance(self.address, IPv4Address) and IPv4Address(0) or IPv6Address(0), 0))

        try:
            data, address = self._sock.recvfrom(bufsize, flags)
            address = (ip_address(unicode(address[0])), address[1])

            # Now that we have the data: always rebind on an address change
            if int(self.address) != int(self._sock_address):
                self.rebind()

            # We have input
            return data, address
        except socket.error:
            # On exception rebind and return an empty response
            self.rebind()
            return ('', (isinstance(self.address, IPv4Address) and IPv4Address(0) or IPv6Address(0), 0))

    def sendto(self, data, flags, address=None):
        # Handle when only two parameters are provided
        if address is None:
            address = flags
            flags = 0

        # Always rebind on an address change
        if int(self.address) != int(self._sock_address):
            self.rebind()

        # Check if we have a real socket
        if self._sock is None:
            if not self.rebind():
                # No socket, no rebind, no data sent
                return 0

        address = (unicode(address[0]), address[1])

        return self._sock.sendto(data, flags, address)
