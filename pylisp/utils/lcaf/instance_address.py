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

    def __init__(self, instance_id=0, address=None, iid_mask_len=32):
        super(LCAFInstanceAddress, self).__init__()
        self.instance_id = instance_id
        self.address = address
        self.iid_mask_len = iid_mask_len

    def sanitize(self):
        super(LCAFInstanceAddress, self).sanitize()

    def __getattr__(self, name):
        return getattr(self.address, name)

    @classmethod
    def _from_data_bytes(cls, data, prefix_len=None, rsvd1=None, flags=None,
                         rsvd2=None):
        instance_id = data.read('uint:32')
        address = read_afi_address_from_bitstream(data)
        if prefix_len is not None:
            address = make_prefix(address, prefix_len)
        lcaf = cls(instance_id=instance_id,
                   address=address)
        lcaf.iid_mask_len = rsvd2.read('uint:8')
        lcaf.sanitize()
        return lcaf

    def _to_data_bytes(self):
        self.sanitize()
        data = BitArray('uint:32=%d' % self.instance_id)
        data += get_bitstream_for_afi_address(self.address)
        return data

    def _to_rsvd2(self):
        return BitArray('uint:8=%d' % self.iid_mask_len)

# Register this class in the registry
type_registry.register_type_class(LCAFInstanceAddress)
