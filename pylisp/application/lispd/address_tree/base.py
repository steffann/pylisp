'''
Created on 10 mrt. 2013

@author: sander
'''
from ipaddress import ip_network
import logging


# Get the logger
logger = logging.getLogger(__name__)


class AbstractNode(object):
    '''
    This is the abstract base class for the lispd address space tree
    '''

    def __init__(self, prefix):
        super(AbstractNode, self).__init__()
        self._prefix = ip_network(prefix)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self._prefix)

    def __hash__(self):
        return hash(self._prefix)

    def __nonzero__(self):
        return True

    @property
    def prefix(self):
        # Return a copy of our prefix
        return ip_network(self._prefix)

    def cleanup(self):
        logger.debug('Cleaning up {0}'.format('%s(%r)' % (self.__class__.__name__, self._prefix)))
