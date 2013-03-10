'''
Created on 2 feb. 2013

@author: sander
'''
from pylisp.utils.represent import represent
import time


class ETRRegistration(object):
    def __init__(self, etr_address, record):
        self._created = time.time()
        self._ttl = 60 * 3

        self.etr_address = etr_address
        self.record = record

    def __repr__(self):
        return represent(self.__class__.__name__, self.__dict__)

    def is_valid(self):
        return time.time() <= self._created + self._ttl
