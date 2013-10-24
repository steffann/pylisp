'''
Created on 3 jun. 2013

@author: sander
'''
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pylisp.application.lispd import settings
import logging


# Get the logger
logger = logging.getLogger(__name__)


def determine_instance_id_and_afi(prefix):
    from pylisp.utils.lcaf.base import LCAFAddress
    from pylisp.utils.lcaf.instance_address import LCAFInstanceAddress

    instance_id = 0
    if isinstance(prefix, LCAFAddress):
        if isinstance(prefix, LCAFInstanceAddress):
            instance_id = prefix.instance_id
        addresses = prefix.get_addresses()

        if len(addresses) != 1:
            logger.warn("Can only determine instance and AFI for one address")
            return (None, None, None)

        prefix = addresses[0]

    # Check AFI
    if isinstance(prefix, (IPv4Address, IPv4Network)):
        afi = 1
    elif isinstance(prefix, (IPv6Address, IPv6Network)):
        afi = 2
    else:
        logger.warn("Received a Map-Request for unknown AFI")
        return (None, None, None)

    # Return dissected elements
    return (instance_id, afi, prefix)


def resolve_path(instance_id, afi, prefix):
    # Check instance_id
    if (instance_id not in settings.config.INSTANCES or afi not in settings.config.INSTANCES[instance_id]):
        return None

    # Look up the prefix
    nodes = settings.config.INSTANCES[instance_id][afi].resolve_path(prefix)
    return nodes


def resolve(instance_id, afi, prefix):
    nodes = resolve_path(instance_id, afi, prefix)
    if nodes is None:
        return None
    return nodes[0]
