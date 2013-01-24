'''
Created on 11 jan. 2013

@author: sander
'''
from abc import abstractmethod, ABCMeta


class ProtocolElement(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        '''
        Constructor
        '''

    def __repr__(self):
        # This works as long as we accept all properties as paramters in the
        # constructor
        params = ['%s=%r' % (k, v) for k, v in self.__dict__.iteritems()]
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(params))

    def __str__(self):
        return str(self.to_bytes())

    def __bytes__(self):
        return self.to_bytes()

    @abstractmethod
    def sanitize(self):
        '''
        Check and optionally fix properties
        '''

    @classmethod
    @abstractmethod
    def from_bytes(cls, bitstream):
        '''
        Parse the given packet and update properties accordingly
        '''

    @abstractmethod
    def to_bytes(self):
        '''
        Create bytes from properties
        '''


class Protocol(ProtocolElement):
    header_type = None

    @abstractmethod
    def __init__(self, next_header=None, payload=''):
        '''
        Constructor
        '''
        super(Protocol, self).__init__()
        self.next_header = next_header
        self.payload = payload

    @abstractmethod
    def sanitize(self):
        '''
        Check and optionally fix properties
        '''
        # Let the parent do its stuff
        super(Protocol, self).sanitize()

        # Check if the next header is of the right type, and fix this header
        # if we know better (i.e. the payload is a ProtocolElement so we know
        # the header_type)
        if isinstance(self.payload, Protocol):
            self.next_header = self.payload.header_type
