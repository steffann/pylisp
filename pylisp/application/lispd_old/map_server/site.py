'''
Created on 30 jan. 2013

@author: sander
'''
from .etr_registration import ETRRegistration
from multiprocessing.dummy import RLock
from pylisp.utils.represent import represent
import logging


# Get the logger
logger = logging.getLogger(__name__)


class Site(object):
    def __init__(self, name, eid_prefixes=None, authentication_key=None,
                 registrations=None):
        self.name = name
        self.eid_prefixes = eid_prefixes or []
        self.authentication_key = authentication_key
        self.registrations = registrations or {}

        self._lock = RLock()

    def __repr__(self):
        return represent(self.__class__.__name__, self.__dict__)

    def update_etr_registration(self, etr_address, record):
        with self._lock:
            self.registrations[etr_address] = ETRRegistration(etr_address,
                                                              record)

    def clean_registrations(self):
        with self._lock:
            old_count = len(self.registrations)
            self.registrations = {etr_address: registration
                                  for etr_address, registration
                                  in self.registrations.iteritems()
                                  if registration.is_valid()}
            new_count = len(self.registrations)
            logger.debug("Site %s: %d of %d registrations "
                         "removed" % (self.name, new_count - old_count,
                                      old_count))
