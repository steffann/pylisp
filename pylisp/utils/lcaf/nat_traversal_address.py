'''
Created on 12 jan. 2013

@author: sander
'''
from bitstring import BitArray
from ipaddress import ip_network
from pylisp.utils.afi import read_afi_address_from_bitstream, \
    get_bitstream_for_afi_address
from pylisp.utils.lcaf import type_registry
from pylisp.utils.lcaf.base import LCAFAddress


class LCAFNATTraversalAddress(LCAFAddress):
    lcaf_type = 7

    def __init__(self, map_server_port=0, etr_port=0, global_etr_rloc=None, map_server_rloc=None,
                 private_etr_rloc=None, rtr_rlocs=None):
        super(LCAFNATTraversalAddress, self).__init__()
        self.map_server_port = map_server_port
        self.etr_port = etr_port
        self.global_etr_rloc = global_etr_rloc
        self.map_server_rloc = map_server_rloc
        self.private_etr_rloc = private_etr_rloc
        self.rtr_rlocs = rtr_rlocs or []

    def __unicode__(self):
        return u'[{0},{1}]{2}'.format(self.longitude, self.latitude, self.address)

    def get_addresses(self):
        return self.rtr_rlocs

    def sanitize(self):
        super(LCAFNATTraversalAddress, self).sanitize()
        # TODO: implement

    @classmethod
    def _from_data_bytes(cls, data, prefix_len=None, rsvd1=None, flags=None, rsvd2=None):
        # These are fixed
        map_server_port, etr_port = data.readlist('2*uint:16')
        global_etr_rloc = read_afi_address_from_bitstream(data)
        map_server_rloc = read_afi_address_from_bitstream(data)
        private_etr_rloc = read_afi_address_from_bitstream(data)

        # The rest of the data is RTR RLOCs
        rtr_rlocs = []
        while data.pos != data.len:
            rtr_rlocs.append(read_afi_address_from_bitstream(data))

        # Build the object
        lcaf = cls(map_server_port=map_server_port,
                   etr_port=etr_port,
                   global_etr_rloc=global_etr_rloc,
                   map_server_rloc=map_server_rloc,
                   private_etr_rloc=private_etr_rloc,
                   rtr_rlocs=rtr_rlocs)
        lcaf.sanitize()
        return lcaf

    def _to_data_bytes(self):
        data = BitArray('uint:16=%d, uint:16=%d' % (self.map_server_port, self.etr_port))
        data += get_bitstream_for_afi_address(self.global_etr_rloc)
        data += get_bitstream_for_afi_address(self.map_server_rloc)
        data += get_bitstream_for_afi_address(self.private_etr_rloc)
        for rtr_rloc in self.rtr_rlocs:
            data += get_bitstream_for_afi_address(rtr_rloc)
        return data


# Register this class in the registry
type_registry.register_type_class(LCAFNATTraversalAddress)
