'''
Created on 11 mrt. 2013

@author: sander
'''


class AddressTreeError(Exception):
    pass


class MapServerNotRegistered(AddressTreeError):
    pass


class DelegationHoleError(AddressTreeError):
    pass


class NotAuthoritativeError(AddressTreeError):
    pass


class MoreSpecificsFoundError(AddressTreeError):
    pass
