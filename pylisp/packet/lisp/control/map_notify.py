'''
Created on 6 jan. 2013

@author: sander
'''
from pylisp.packet.lisp.control import type_registry, MapRegisterMessage


__all__ = ['MapNotifyMessage']


class MapNotifyMessage(MapRegisterMessage):
    # Class property: which message type do we represent?
    message_type = 4


# Register this class in the registry
type_registry.register_type_class(MapNotifyMessage)
