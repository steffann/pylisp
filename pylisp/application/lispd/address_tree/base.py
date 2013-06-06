'''
Created on 10 mrt. 2013

@author: sander
'''
from ipaddress import ip_network
import logging
import threading


# Get the logger
logger = logging.getLogger(__name__)


class AbstractNode(object):
    '''
    This is the abstract base class for the lispd address space tree
    '''

    def __init__(self, prefix):
        super(AbstractNode, self).__init__()
        self.prefix = ip_network(prefix)

        # Create a lock for this object
        self.lock = threading.RLock()

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.prefix)

    def __hash__(self):
        return hash(self.prefix)

    def __nonzero__(self):
        return True

    def process(self, control_plane_sockets, data_plane_sockets):
        logger.debug('Processing {0}'.format('%s(%r)' % (self.__class__.__name__, self.prefix)))


class AddressTreeError(Exception):
    pass


class MapServerNotRegistered(AddressTreeError):
    pass


class DelegationHoleError(AddressTreeError):
    pass


class NotAuthoritativeError(AddressTreeError):
    pass


class MoreSpecificsFoundError(AddressTreeError):
    pass
