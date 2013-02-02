'''
Created on 30 jan. 2013

@author: sander
'''
import logging
from multiprocessing.dummy import RLock


# Get the logger
logger = logging.getLogger(__name__)


class Site(object):
    def __init__(self, name, eid_prefixes=None, authentication_key=None,
                 registrations=None):
        self.name = name
        self.eid_prefixes = eid_prefixes or []
        self.authentication_key = authentication_key
        self.registrations = registrations or []

        self._lock = RLock()

    # def update_etr_registration(self, etr_addr, ):
