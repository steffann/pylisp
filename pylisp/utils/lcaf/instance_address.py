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


class LCAFInstanceAddress(LCAFAddress):
    lcaf_type = 2

    def __init__(self, instance_id=0, address=None):
        super(LCAFInstanceAddress, self).__init__()
        self.instance_id = instance_id
        self.address = address

    def sanitize(self):
        super(LCAFInstanceAddress, self).sanitize()

    @classmethod
    def _from_data_bytes(cls, data, prefix_len=None):
        instance_id = data.read('uint:32')
        address = read_afi_address_from_bitstream(data)
        if prefix_len is not None:
            address = make_prefix(address, prefix_len)
        lcaf = cls(instance_id=instance_id,
                   address=address)
        lcaf.sanitize()
        return lcaf

    def _to_data_bytes(self):
        data = BitArray('uint:32=%d' % self.instance_id)
        data += get_bitstream_for_afi_address(self.address)
        return data


# Register this class in the registry
type_registry.register_type_class(LCAFInstanceAddress)
