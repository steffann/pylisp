'''
Created on 7 jan. 2013

@author: sander
'''

# The following Key ID values are defined by this specification as used
# in any packet type that references a Key ID field:
#
# Name                 Number          Defined in
#-----------------------------------------------
# None                 0               n/a
# HMAC-SHA-1-96        1               [RFC2404]
# HMAC-SHA-256-128     2               [RFC6234]

KEY_ID_NONE = 0
KEY_ID_HMAC_SHA_1_96 = 1
KEY_ID_HMAC_SHA_256_128 = 2

# The actions defined are used by an ITR or PITR when a
# destination EID matches a negative mapping cache entry.
# Unassigned values should cause a map-cache entry to be created
# and, when packets match this negative cache entry, they will be
# dropped.  The current assigned values are:
#
# (0) No-Action:  The map-cache is kept alive and no packet
#    encapsulation occurs.
#
# (1) Natively-Forward:  The packet is not encapsulated or dropped
#    but natively forwarded.
#
# (2) Send-Map-Request:  The packet invokes sending a Map-Request.
#
# (3) Drop:  A packet that matches this map-cache entry is dropped.
#    An ICMP Unreachable message SHOULD be sent.

NMRA_NO_ACTION = 0
NMRA_NATIVELY_FORWARD = 1
NMRA_SEND_MAP_REQUEST = 2
NMRA_DROP = 3
