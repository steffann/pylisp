'''
Created on 6 jan. 2013

@author: sander
'''
from pylisp.packet.control import type_registry
from pylisp.packet.control.map_register import LISPMapRegisterPacket


__all__ = ['LISPMapNotifyPacket']


class LISPMapNotifyPacket(LISPMapRegisterPacket):
    # Class property: which message type do we represent?
    message_type = 4


# Register this class in the registry
type_registry.register_type_class(LISPMapNotifyPacket)