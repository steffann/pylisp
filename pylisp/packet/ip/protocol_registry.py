'''
Created on 6 jan. 2013

@author: sander
'''
import numbers
from pylisp.packet.ip.protocol import Protocol


# Store supported protocol types and their classes
_type_classes = {}


__all__ = ['register_type_class', 'get_type_class']


def register_type_class(type_class):
    # Check for valid class
    if not issubclass(type_class, Protocol):
        msg = 'Message type classes must be subclasses of Protocol'
        raise ValueError(msg)

    # Check for valid type numbers
    type_nr = type_class.header_type

    if not isinstance(type_nr, numbers.Integral) \
    or type_nr < 0 or type_nr > 255:
        raise ValueError('Invalid protocol {0}'.format(type_nr))

    # Check for duplicates
    if type_nr in _type_classes:
        # Ignore identical registrations
        if type_class is _type_classes[type_nr]:
            return

        msg = 'Protocol {0} is already bound to class {1}'
        class_name = _type_classes[type_nr].__name__
        raise ValueError(msg.format(type_nr, class_name))

    _type_classes[type_nr] = type_class


def get_type_class(type_nr):
    return _type_classes.get(type_nr)
