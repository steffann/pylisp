#!/usr/bin/env python
from pylisp.utils import lcaf
from IPy import IP
from pylisp.utils.lcaf.base import LCAFAddress
from pylisp.utils.afi import get_bitstream_for_afi_address, \
    read_afi_address_from_bitstream

addresses = [lcaf.LCAFNullAddress(),
             lcaf.LCAFAFIListAddress(addresses=[IP('192.0.2.1'),
                                                IP('2001:db8::1')]),
             lcaf.LCAFInstanceAddress(instance_id=100,
                                      address=IP('192.0.2.100')),
             lcaf.LCAFAutonomousSystemAddress(asn=57771,
                                              address=IP('37.77.56.75')),
             lcaf.LCAFGeoAddress(north=True,
                                 latitude_degrees=52,
                                 latitude_minutes=12,
                                 latitude_seconds=29,
                                 east=True,
                                 longitude_degrees=5,
                                 longitude_minutes=56,
                                 longitude_seconds=53,
                                 altitude=0 - 10)]

for address in addresses:
    print 'Original:   %r' % address

    address_bytes = bytes(address)
    address2 = LCAFAddress.from_bytes(address_bytes)

    print 'Re-parsed:  %r' % address2
    print 'Match:      %s' % (address.__class__ == address2.__class__ and
                             address.__dict__ == address2.__dict__)

    afi_bitstream = get_bitstream_for_afi_address(address)
    afi_bytes = afi_bitstream.bytes
    address3 = read_afi_address_from_bitstream(afi_bytes)

    print 'AFI-parsed: %r' % address3
    print 'Match:      %s' % (address.__class__ == address3.__class__ and
                              address.__dict__ == address3.__dict__)

    if isinstance(address, lcaf.LCAFGeoAddress):
        print 'Lat: %0.3f' % address.latitude
        print 'Lon: %0.3f' % address.longitude

    print
