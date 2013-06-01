#!/usr/bin/env python
from ipaddress import ip_address, ip_network, IPv4Network, IPv6Network
from pylisp.application.lispd.address_tree.authoritative_container_node import AuthoritativeContainerNode
from pylisp.application.lispd.address_tree.container_node import ContainerNode
from pylisp.application.lispd.address_tree.ddt_referral_node import DDTReferralNode
import logging
import re


# Get the logger
logger = logging.getLogger(__name__)


ddt_line = re.compile(r'^(?P<instance>[0-9]+)\s+'
                      r'(?P<afi>[0-9]+)\s+'
                      r'(?P<prefix>[0-9a-fA-F.:/]+)\s+'
                      r'(?P<address>[0-9a-fA-F.:]+)$')


def add_delegation(instances, instance_id, afi, prefix, address):
    if instance_id not in instances:
        logger.debug('Adding instance {0}'.format(instance_id))
        instances[instance_id] = {}

    if afi not in instances[instance_id]:
        if afi == 1:
            instances[instance_id][afi] = AuthoritativeContainerNode(u'0.0.0.0/0')
        elif afi == 2:
            instances[instance_id][afi] = AuthoritativeContainerNode(u'::/0')
        else:
            raise ValueError('Unknown AFI {0}'.format(afi))

    best_match = instances[instance_id][afi].resolve(prefix)
    if isinstance(best_match, DDTReferralNode):
        logger.debug('Updating DDT referral for instance {0} prefix {1}, adding node {2}'.format(instance_id, prefix,
                                                                                                 address))

        # There already is a DDTReferralNode, check prefix and add
        if best_match.prefix != prefix:
            raise ValueError('Cannot add overlapping prefix {0} to existing referral {1}'
                             ' in instance {2}'.format(prefix, best_match, instance_id))
        best_match.add(address)

    elif isinstance(best_match, ContainerNode):
        logger.debug('Adding DDT referral for instance {0} prefix {1} to node {2}'.format(instance_id, prefix,
                                                                                          address))

        # Add a new DDTReferralNode to the container
        best_match.add(DDTReferralNode(prefix, [address]))

    else:
        raise ValueError('Overlapping node of unrecognised type {0}'.format(best_match))


def load_ddt_root(filename):
    instances = {}
    ddt_root = file(filename)

    for line in ddt_root:
        line = line.split('#')[0].strip()
        if not line:
            continue

        match = ddt_line.match(line)
        if not match:
            raise ValueError('Invalid ddt_root line: "{0}"'.format(line))

        groups = match.groupdict()
        instance_id = int(groups['instance'])
        afi = int(groups['afi'])
        address = ip_address(unicode(groups['address']))

        try:
            if afi == 0:
                # If AFI is 0 then add wildcard references for both IPv4 and IPv6
                add_delegation(instances, instance_id, 1, IPv4Network(u'0.0.0.0/0'), address)
                add_delegation(instances, instance_id, 2, IPv6Network(u'::/0'), address)
            else:
                prefix = ip_network(unicode(groups['prefix']))
                add_delegation(instances, instance_id, afi, prefix, address)
        except ValueError, e:
            raise ValueError('{0} in ddt_root line {1}'.format(e, line))

    return instances
