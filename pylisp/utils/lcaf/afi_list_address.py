'''
Created on 12 jan. 2013

@author: sander
'''
from pylisp.utils.lcaf.base import LCAFAddress
from pylisp.utils.lcaf import type_registry
from pylisp.utils.afi import read_afi_address_from_bitstream, \
    get_bitstream_for_afi_address
from bitstring import BitArray


class LCAFAFIListAddress(LCAFAddress):
    lcaf_type = 1

    def __init__(self, addresses=None):
        super(LCAFAFIListAddress, self).__init__()
        self.addresses = addresses or []

    def sanitize(self):
        super(LCAFAFIListAddress, self).sanitize()

    @classmethod
    def _from_data_bytes(cls, data):
        addresses = []
        while data.pos != data.len:
            address = read_afi_address_from_bitstream(data)
            addresses.append(address)
        lcaf = cls(addresses=addresses)
        lcaf.sanitize()
        return lcaf

    def _to_data_bytes(self):
        data = BitArray()
        for address in self.addresses:
            data += get_bitstream_for_afi_address(address)
        return data


# Register this class in the registry
type_registry.register_type_class(LCAFAFIListAddress)
