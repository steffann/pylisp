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


class LCAFGeoAddress(LCAFAddress):
    lcaf_type = 5

    def __init__(self, north=False, latitude_degrees=0, latitude_minutes=0,
                 latitude_seconds=0, east=False, longitude_degrees=0,
                 longitude_minutes=0, longitude_seconds=0, altitude=0x7fffffff,
                 address=None):
        super(LCAFGeoAddress, self).__init__()
        self.north = north
        self.latitude_degrees = latitude_degrees
        self.latitude_minutes = latitude_minutes
        self.latitude_seconds = latitude_seconds
        self.east = east
        self.longitude_degrees = longitude_degrees
        self.longitude_minutes = longitude_minutes
        self.longitude_seconds = longitude_seconds
        self.altitude = altitude
        self.address = address

    def _get_latitude(self):
        return (self.latitude_degrees +
                (self.latitude_minutes / 60.0) +
                (self.latitude_seconds / 3600.0))

    def _set_latitude(self, latitude):
        self.latitude_degrees = int(latitude)
        minutes = (latitude % 1) * 60
        self.latitude_minutes = int(minutes)
        seconds = (minutes % 1) * 60
        self.latitude_seconds = int(round(seconds))

    latitude = property(fget=_get_latitude, fset=_set_latitude)

    def _get_longitude(self):
        return (self.longitude_degrees +
                (self.longitude_minutes / 60.0) +
                (self.longitude_seconds / 3600.0))

    def _set_longitude(self, longitude):
        self.longitude_degrees = int(longitude)
        minutes = (longitude % 1) * 60
        self.longitude_minutes = int(minutes)
        seconds = (minutes % 1) * 60
        self.longitude_seconds = int(round(seconds))

    longitude = property(fget=_get_longitude, fset=_set_longitude)

    def sanitize(self):
        super(LCAFGeoAddress, self).sanitize()

    @classmethod
    def _from_data_bytes(cls, data, prefix_len=None, rsvd1=None, flags=None,
                         rsvd2=None):
        (north, latitude_degrees, latitude_minutes,
         latitude_seconds) = data.readlist('bool, uint:15, 2*uint:8')
        (east, longitude_degrees, longitude_minutes,
         longitude_seconds) = data.readlist('bool, uint:15, 2*uint:8')
        altitude = data.read('int:32')
        address = read_afi_address_from_bitstream(data)
        if prefix_len is not None:
            address = make_prefix(address, prefix_len)
        lcaf = cls(north=north,
                   latitude_degrees=latitude_degrees,
                   latitude_minutes=latitude_minutes,
                   latitude_seconds=latitude_seconds,
                   east=east,
                   longitude_degrees=longitude_degrees,
                   longitude_minutes=longitude_minutes,
                   longitude_seconds=longitude_seconds,
                   altitude=altitude,
                   address=address)
        lcaf.sanitize()
        return lcaf

    def _to_data_bytes(self):
        data = BitArray('bool=%d, uint:15=%d, uint:8=%d, '
                        'uint:8=%d' % (self.north,
                                       self.latitude_degrees,
                                       self.latitude_minutes,
                                       self.latitude_seconds))
        data += BitArray('bool=%d, uint:15=%d, uint:8=%d, '
                         'uint:8=%d' % (self.east,
                                        self.longitude_degrees,
                                        self.longitude_minutes,
                                        self.longitude_seconds))
        data += BitArray('int:32=%d' % self.altitude)
        data += get_bitstream_for_afi_address(self.address)
        return data


# Register this class in the registry
type_registry.register_type_class(LCAFGeoAddress)
