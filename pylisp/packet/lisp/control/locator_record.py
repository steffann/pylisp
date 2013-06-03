'''
Created on 6 jan. 2013

@author: sander
'''
from bitstring import ConstBitStream, BitArray, Bits
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from pylisp.application.lispd.utils.prefix import determine_instance_id_and_afi
from pylisp.utils.afi import read_afi_address_from_bitstream, get_bitstream_for_afi_address
from pylisp.utils.lcaf.base import LCAFAddress
from pylisp.utils.represent import represent
import numbers


__all__ = ['LocatorRecord']


class LocatorRecord(object):
    def __init__(self, priority=255, weight=0, m_priority=255, m_weight=0,
                 local=False, probed_locator=False, reachable=False,
                 address=None):
        '''
        Constructor
        '''
        # Set defaults
        self.priority = priority
        self.weight = weight
        self.m_priority = m_priority
        self.m_weight = m_weight
        self.local = local
        self.probed_locator = probed_locator
        self.reachable = reachable
        self.address = address

        # Store space for reserved bits
        self._reserved1 = BitArray(13)

    @staticmethod
    def sort_key(locator):
        # Provide a key that can be used for sorting
        dummy, dummy, address = determine_instance_id_and_afi(locator.address)
        return int(address)

    def __repr__(self):
        return represent(self.__class__.__name__, self.__dict__)

    def sanitize(self):
        '''
        Check if the current settings conform to the LISP specifications and
        fix where possible.
        '''
        # Priority:  each RLOC is assigned a unicast priority.  Lower values
        # are more preferable.  When multiple RLOCs have the same priority,
        # they MAY be used in a load-split fashion.  A value of 255 means
        # the RLOC MUST NOT be used for unicast forwarding.
        if not isinstance(self.priority, numbers.Integral) \
        or self.priority < 0 or self.priority > 255:
            raise ValueError('Invalid priority')

        # Weight:  when priorities are the same for multiple RLOCs, the weight
        # indicates how to balance unicast traffic between them.  Weight is
        # encoded as a relative weight of total unicast packets that match
        # the mapping entry.  For example if there are 4 locators in a
        # locator set, where the weights assigned are 30, 20, 20, and 10,
        # the first locator will get 37.5% of the traffic, the 2nd and 3rd
        # locators will get 25% of traffic and the 4th locator will get
        # 12.5% of the traffic.  If all weights for a locator-set are equal,
        # receiver of the Map-Reply will decide how to load-split traffic.
        # See Section 6.5 for a suggested hash algorithm to distribute load
        # across locators with same priority and equal weight values.
        #
        # WARNING: Cisco implementations limit the weight to the range 0-100
        if not isinstance(self.weight, numbers.Integral) \
        or self.weight < 0 or self.weight > 255:
            raise ValueError('Invalid weight')

        # M Priority:  each RLOC is assigned a multicast priority used by an
        # ETR in a receiver multicast site to select an ITR in a source
        # multicast site for building multicast distribution trees.  A value
        # of 255 means the RLOC MUST NOT be used for joining a multicast
        # distribution tree.  For more details, see [MLISP].
        if not isinstance(self.m_priority, numbers.Integral) \
        or self.m_priority < 0 or self.m_priority > 255:
            raise ValueError('Invalid multicast priority')

        # M Weight:  when priorities are the same for multiple RLOCs, the
        # weight indicates how to balance building multicast distribution
        # trees across multiple ITRs.  The weight is encoded as a relative
        # weight (similar to the unicast Weights) of total number of trees
        # built to the source site identified by the EID-prefix.  If all
        # weights for a locator-set are equal, the receiver of the Map-Reply
        # will decide how to distribute multicast state across ITRs.  For
        # more details, see [MLISP].
        if not isinstance(self.m_weight, numbers.Integral) \
        or self.m_weight < 0 or self.m_weight > 255:
            raise ValueError('Invalid weight')

        # L: when this bit is set, the locator is flagged as a local locator to
        # the ETR that is sending the Map-Reply.  When a Map-Server is doing
        # proxy Map-Replying [LISP-MS] for a LISP site, the L bit is set to
        # 0 for all locators in this locator-set.
        if not isinstance(self.local, bool):
            raise ValueError('Local flag must be a boolean')

        # p: when this bit is set, an ETR informs the RLOC-probing ITR that the
        # locator address, for which this bit is set, is the one being RLOC-
        # probed and MAY be different from the source address of the Map-
        # Reply.  An ITR that RLOC-probes a particular locator, MUST use
        # this locator for retrieving the data structure used to store the
        # fact that the locator is reachable.  The "p" bit is set for a
        # single locator in the same locator set.  If an implementation sets
        # more than one "p" bit erroneously, the receiver of the Map-Reply
        # MUST select the first locator.  The "p" bit MUST NOT be set for
        # locator-set records sent in Map-Request and Map-Register messages.
        if not isinstance(self.probed_locator, bool):
            raise ValueError('Probed Locator flag must be a boolean')

        # R: set when the sender of a Map-Reply has a route to the locator in
        # the locator data record.  This receiver may find this useful to
        # know if the locator is up but not necessarily reachable from the
        # receiver's point of view.  See also Section 6.4 for another way
        # the R-bit may be used.
        if not isinstance(self.reachable, bool):
            raise ValueError('Reachable flag must be a boolean')

        # Locator:  an IPv4 or IPv6 address (as encoded by the 'Loc-AFI' field)
        # assigned to an ETR.  Note that the destination RLOC address MAY be
        # an anycast address.  A source RLOC can be an anycast address as
        # well.  The source or destination RLOC MUST NOT be the broadcast
        # address (255.255.255.255 or any subnet broadcast address known to
        # the router), and MUST NOT be a link-local multicast address.  The
        # source RLOC MUST NOT be a multicast address.  The destination RLOC
        # SHOULD be a multicast address if it is being mapped from a
        # multicast destination EID.

        if isinstance(self.address, (IPv4Address, IPv6Address)):
            addresses = [self.address]
        elif isinstance(self.address, LCAFAddress):
            addresses = self.address.get_addresses()
        else:
            raise ValueError('Locator must be an (LCAF) IPv4 or IPv6 address')

        for address in addresses:
            if isinstance(self.address, IPv4Address):
                if address == IPv4Address(u'255.255.255.255'):
                    raise ValueError('Locator must not be the broadcast '
                                     'address')

                if address in IPv4Network(u'224.0.0.0/24'):
                    raise ValueError('Locator must not be a link-local '
                                     'multicast address')

            elif isinstance(self.address, IPv6Address):
                if address in IPv6Network(u'ff02::/16') \
                or address in IPv6Network(u'ff12::/16'):
                    raise ValueError('Locator must not be a link-local '
                                     'multicast address')

            else:
                raise ValueError('Locator must be an IPv4 or IPv6 address')

    @classmethod
    def from_bytes(cls, bitstream):
        '''
        Parse the given record and update properties accordingly
        '''
        record = cls()

        # Convert to ConstBitStream (if not already provided)
        if not isinstance(bitstream, ConstBitStream):
            if isinstance(bitstream, Bits):
                bitstream = ConstBitStream(auto=bitstream)
            else:
                bitstream = ConstBitStream(bytes=bitstream)

        # Read the priorities and weights
        (record.priority, record.weight, record.m_priority,
         record.m_weight) = bitstream.readlist('4*uint:8')

        # Read over unused flags
        record._reserved1 = bitstream.read(13)

        # Read the flags
        (record.local,
         record.probed_locator,
         record.reachable) = bitstream.readlist('3*bool')

        # Read the locator
        record.address = read_afi_address_from_bitstream(bitstream)

        # Verify that the properties make sense
        record.sanitize()

        return record

    def to_bytes(self):
        '''
        Create bytes from properties
        '''
        return self.to_bitstream().bytes

    def to_bitstream(self):
        '''
        Create bitstream from properties
        '''
        # Verify that properties make sense
        self.sanitize()

        # Start with the priorities and weights
        bitstream = BitArray('uint:8=%d, uint:8=%d, uint:8=%d, '
                             'uint:8=%d' % (self.priority,
                                            self.weight,
                                            self.m_priority,
                                            self.m_weight))

        # Add padding
        bitstream += self._reserved1

        # Add the flags
        bitstream += BitArray('bool=%d, bool=%d, bool=%d'
                              % (self.local,
                                 self.probed_locator,
                                 self.reachable))

        # Add the locator
        bitstream += get_bitstream_for_afi_address(self.address)

        return bitstream
