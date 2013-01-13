'''
Created on 12 jan. 2013

@author: sander
'''
from bitstring import BitArray
from pylisp.utils import make_prefix
from pylisp.utils.afi import read_afi_address_from_bitstream, \
    get_bitstream_for_afi_address
from pylisp.utils.lcaf import type_registry
from pylisp.utils.lcaf.base import LCAFAddress


class LCAFAutonomousSystemAddress(LCAFAddress):
    lcaf_type = 3

    def __init__(self, asn=0, address=None):
        super(LCAFAutonomousSystemAddress, self).__init__()
        self.asn = asn
        self.address = address

    def sanitize(self):
        super(LCAFAutonomousSystemAddress, self).sanitize()

    @classmethod
    def _from_data_bytes(cls, data, prefix_len=None):
        asn = data.read('uint:32')
        address = read_afi_address_from_bitstream(data)
        if prefix_len is not None:
            address = make_prefix(address, prefix_len)
        lcaf = cls(asn=asn,
                   address=address)
        lcaf.sanitize()
        return lcaf

    def _to_data_bytes(self):
        data = BitArray('uint:32=%d' % self.asn)
        data += get_bitstream_for_afi_address(self.address)
        return data


# Register this class in the registry
type_registry.register_type_class(LCAFAutonomousSystemAddress)
