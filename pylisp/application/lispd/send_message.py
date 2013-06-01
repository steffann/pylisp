'''
Created on 2 jun. 2013

@author: sander
'''
from ipaddress import ip_address, IPv4Address
import logging
import socket


# Get the logger
logger = logging.getLogger(__name__)


def send_message(message, my_sockets, destinations, port=4342):
    # Find an appropriate destination
    for destination in destinations:
        destination = ip_address(unicode(destination))
        dest_family = (isinstance(destination, IPv4Address)
                       and socket.AF_INET
                       or socket.AF_INET6)
        for sock in my_sockets:
            if sock.family == dest_family:
                addr = (str(destination), port)
                data = bytes(message)
                logger.debug("Sending %d bytes to %s", len(data), addr)
                sent = sock.sendto(data, addr)
                return (sent == len(data))
