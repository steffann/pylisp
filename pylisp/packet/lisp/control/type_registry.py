'''
Created on 6 jan. 2013

@author: sander
'''
import numbers
from pylisp.packet.lisp.control import ControlMessage

# Store supported message types and their classes
_type_classes = {}


__all__ = ['register_type_class', 'get_type_class']


def register_type_class(type_class):
    # Check for valid class
    if not issubclass(type_class, ControlMessage):
        msg = 'Message type classes must be subclasses of ControlMessage'
        raise ValueError(msg)

    # Check for valid type numbers
    type_nr = type_class.message_type

    if not isinstance(type_nr, numbers.Integral) \
    or type_nr <= 0 or type_nr > 15:
        raise ValueError('Invalid message type {0}'.format(type_nr))

    # Check for duplicates
    if type_nr in _type_classes:
        # Ignore identical registrations
        if type_class is _type_classes[type_nr]:
            return

        msg = 'Message type {0} is already bound to class {1}'
        class_name = _type_classes[type_nr].__name__
        raise ValueError(msg.format(type_nr, class_name))

    _type_classes[type_nr] = type_class


def get_type_class(type_nr):
    return _type_classes.get(type_nr)
