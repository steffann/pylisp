'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import ip_address, IPv4Address
import logging
import socket


# Get the logger
logger = logging.getLogger(__name__)


def find_matching_sockets(destination, my_sockets):
    dest_family = (isinstance(destination, IPv4Address)
                   and socket.AF_INET
                   or socket.AF_INET6)

    matches = []
    for sock in my_sockets:
        if sock.family == dest_family:
            matches.append(sock)

    return matches


def find_matching_addresses(destination, my_sockets):
    sockets = find_matching_sockets(destination, my_sockets)
    addresses = [ip_address(unicode(sock.getsockname()[0])) for sock in sockets]
    return addresses


def send_message(message, my_sockets, destinations, port=4342):
    # Find an appropriate destination
    for destination in destinations:
        destination = ip_address(unicode(destination))
        for sock in find_matching_sockets(destination, my_sockets):
            addr = (destination, port)
            data = bytes(message)
            logger.debug(u"Sending {0} from {1} to {2}".format(message.__class__.__name__,
                                                               sock.getsockname()[0],
                                                               destination))
            sent = sock.sendto(data, addr)
            if sent == len(data):
                return sock.getsockname()[0:2], addr

            logger.warning("Could not send from {0} to {1}".format(sock.getsockname()[0], destination))

    return None, None
