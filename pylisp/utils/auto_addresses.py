'''
Created on 4 jun. 2013

@author: sander
'''
from abc import ABCMeta
from ipaddress import IPv4Address, IPv6Address, ip_address
import logging
import netifaces
import weakref


__all__ = ['AutoIPv4Address', 'AutoIPv6Address', 'get_ipv4_address', 'get_ipv6_address', 'update_addresses']


# Get the logger
logger = logging.getLogger(__name__)


# Store weak references to addresses so we can trigger updates on changes
_all_auto_addresses = weakref.WeakSet()


def update_addresses():
    """
    Update all AutoAddresses
    """
    global _all_auto_addresses
    for address in _all_auto_addresses:
        address.update_address()


class AutoAddress(object):
    __meta__ = ABCMeta

    def __init__(self, if_name):
        # Store the interface name
        self._if_name = if_name

        # Remember who wants to be notified on change
        self._notify_targets = weakref.WeakSet()

        # Register myself so updates can be triggered
        global _all_auto_addresses
        _all_auto_addresses.add(self)

        # And update
        self.update_address()

    def __repr__(self):
        return u"{0}({1})".format(self.__class__.__name__, self._if_name)

    def __hash__(self):
        # The address is mutable, the interface name isn't
        return hash(self._if_name)

    def add_notify_target(self, notify_target):
        self._notify_targets.add(notify_target)

    def _send_notifications(self):
        for notify_target in self._notify_targets:
            try:
                notify_target.on_address_change(self)
            except:
                logger.exception("{0!r} notify target {1!r} has thrown an exception".format(self, notify_target))

    def update_address(self):
        logger.debug("Updating {0!r}".format(self))

        # Zero address as fall-back
        new_ip = 0

        try:
            # Find the first suitable address
            addresses = netifaces.ifaddresses(self._if_name)[self._address_family]  # @UndefinedVariable
            for potential_address in addresses:
                # Get the address out of the dict and strip away any scope-id
                potential_address = potential_address['addr'].split('%')[0]

                # Convert to a proper object
                potential_address = ip_address(unicode(potential_address))

                logger.debug("Found potential address {0} for {1!r}".format(potential_address, self))

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
            logger.info("No address found for {0!r}".format(self))
            pass

        orig_ip = self._ip
        if orig_ip == new_ip:
            if new_ip == 0:
                logger.info("Still no address found for {0!r}".format(self))
            else:
                logger.info("Still using address {0} for {1!r}".format(str(self), self))
        else:
            if new_ip == 0:
                logger.info("No usable {0} found for {1!r}".format(self.__class__.__name__, self))
            else:
                logger.info("Using address {0} for {1!r}".format(potential_address, self))

            # Store the new IP address and notify listeners
            self._ip = new_ip
            self._send_notifications()


class AutoIPv4Address(AutoAddress, IPv4Address):
    """
    Automatically determines the 'first' IPv4 address of an interface and
    provides compatibility with ipaddress.IPv4Address.
    """
    _address_family = netifaces.AF_INET  # @UndefinedVariable

    def __init__(self, if_name):
        IPv4Address.__init__(self, 0)
        AutoAddress.__init__(self, if_name)


class AutoIPv6Address(AutoAddress, IPv6Address):
    """
    Automatically determines the 'first' IPv6 address of an interface and
    provides compatibility with ipaddress.IPv6Address.
    """
    _address_family = netifaces.AF_INET6  # @UndefinedVariable

    def __init__(self, if_name):
        IPv6Address.__init__(self, 0)
        AutoAddress.__init__(self, if_name)


# Define a local cache of auto-addresses
_auto_ipv4_cache = {}
_auto_ipv6_cache = {}


def get_ipv4_address(if_name):
    global _auto_ipv4_cache

    if if_name in _auto_ipv4_cache:
        address = _auto_ipv4_cache[if_name]
        logger.debug("Used existing {0!r} from the cache".format(_auto_ipv4_cache[if_name]))
    else:
        address = AutoIPv4Address(if_name)
        _auto_ipv4_cache[if_name] = address
        logger.debug("Created new {0!r} and put it in the cache".format(_auto_ipv4_cache[if_name]))

    return address


def get_ipv6_address(if_name):
    global _auto_ipv6_cache

    if if_name in _auto_ipv6_cache:
        address = _auto_ipv6_cache[if_name]
        logger.debug("Used existing {0!r} from the cache".format(_auto_ipv6_cache[if_name]))
    else:
        address = AutoIPv6Address(if_name)
        _auto_ipv6_cache[if_name] = address
        logger.debug("Created new {0!r} and put it in the cache".format(_auto_ipv6_cache[if_name]))

    return address
