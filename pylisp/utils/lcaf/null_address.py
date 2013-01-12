'''
Created on 12 jan. 2013

@author: sander
'''
from pylisp.utils.lcaf.base import LCAFAddress
from pylisp.utils.lcaf import type_registry
from bitstring import BitArray


class LCAFNullAddress(LCAFAddress):
    lcaf_type = 0

    def __init__(self):
        super(LCAFNullAddress, self).__init__()

    def sanitize(self):
        super(LCAFNullAddress, self).sanitize()

    @classmethod
    def _from_data_bytes(cls, data):
        lcaf = cls()
        lcaf.sanitize()
        return lcaf

    def _to_data_bytes(self):
        return BitArray(0)


# Register this class in the registry
type_registry.register_type_class(LCAFNullAddress)
