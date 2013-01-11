'''
Created on 6 jan. 2013

@author: sander
'''
from pylisp.utils.afi import read_afi_address_from_bitstream
from IPy import IP


# TODO: This should really be put into a class structure


class LCAFInstanceIP(IP):
    def __init__(self, data, ipversion=0, make_net=0, instance_id=0):
        IP.__init__(self, data, ipversion=ipversion, make_net=make_net)
        self.instance_id = instance_id


class LCAFAutonomousSystemIP(IP):
    def __init__(self, data, ipversion=0, make_net=0, asn=0):
        IP.__init__(self, data, ipversion=ipversion, make_net=make_net)
        self.asn = asn


def read_lcaf_address_from_bitstream(bitstream, prefix_len=None):
    '''
    This function decodes an LCAF address from a readable bitstream
    '''

    # Skip over reserved bits
    bitstream.read(8)

    # Skip over the (unused) flags
    bitstream.read(8)

    # Read the type
    lcaf_type = bitstream.read('uint:8')

    # Skip over reserved bits
    bitstream.read(8)

    # Read the length
    length = bitstream.read('uint:16')

    # Get the data
    data = bitstream.read(length * 8)

    # Process the data
    if lcaf_type == 0:
        return None
    elif lcaf_type == 1:
        addresses = []
        while data.pos != data.len:
            address = read_afi_address_from_bitstream(data)
            addresses.append(address)
        return addresses
    elif lcaf_type == 2:
        instance_id = data.read('uint:32')
        address = read_afi_address_from_bitstream(data)
        return LCAFInstanceIP(address, instance_id=instance_id)
    elif lcaf_type == 3:
        asn = data.read('uint:32')
        address = read_afi_address_from_bitstream(data)
        return LCAFAutonomousSystemIP(address, asn=asn)
    elif lcaf_type == 4:
        tos_tc_flowlabel = data.read('uint:24')
        protocol = data.read('uint:8')
        local_port, remote_port = data.readlist('2*uint:16')
        address = read_afi_address_from_bitstream(data)
        return {'tos_tc_flowlabel': tos_tc_flowlabel,
                'protocol': protocol,
                'local_port': local_port,
                'remote_port': remote_port,
                'address': address}
    elif lcaf_type == 5:
        (north, latitude_degrees, latitude_minutes,
         latitude_seconds) = data.readlist('bool, uint:15, 2*uint:8')
        (east, longitude_degrees, longitude_minutes,
         longitude_seconds) = data.readlist('bool, uint:15, 2*uint:8')
        altitude = data.read('uint:32')
        address = read_afi_address_from_bitstream(data)
        return {'north': north,
                'latitude_degrees': latitude_degrees,
                'latitude_minutes': latitude_minutes,
                'latitude_seconds': latitude_seconds,
                'east': east,
                'longitude_degrees': longitude_degrees,
                'longitude_minutes': longitude_minutes,
                'longitude_seconds': longitude_seconds,
                'altitude': altitude,
                'address': address}
    elif lcaf_type == 6:
        return {'key': data.bytes}
    else:
        # Just give back the damn data
        return {'type': lcaf_type,
                'data': data.bytes}


def get_bitstream_for_lcaf_address(address):
    raise NotImplementedError('Cannot encode LCAF addresses yet')
