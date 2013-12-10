'''
Created on 15 jan. 2013

@author: sander
'''
from ipaddress import ip_address, IPv4Address, IPv6Address, IPv4Network, IPv6Network
from pylisp.application.lispd.address_tree.container_node import ContainerNode
from pylisp.application.lispd.utils import id_generators
from pylisp.utils import afi
from types import NoneType
import imp
import logging
import os
import socket
import sys


# Get the logger
logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    pass


class Settings(object):
    def __init__(self, only_defaults=False):
        # Someone might want to know if there is more than the defaults
        self.only_defaults = only_defaults

        # A list of IP addresses
        self.LISTEN_ON = self.default_listen_on()

        # A list of instances. The key is the instance-id, the value a dict
        # of AFI-ids pointing to ContainerNodes.
        self.INSTANCES = {}

        # An IPv4Address or IPv6Address of the PETR
        self.PETR = None

        # Enable NAT and RTR detection
        self.NATT = True

        # The NF-Queue IDs for IPv4 and IPv6
        self.NFQUEUE_IPV4 = None
        self.NFQUEUE_IPV6 = None

        # xTR-ID and Site-ID
        self.XTR_ID = id_generators.get_xtr_id()
        self.SITE_ID = 0

        # Do we process data?
        self.PROCESS_DATA = True

        if not self.only_defaults:
            # Apply the config
            self.apply_config_files()

    def default_listen_on(self):
        # Listen to the IP addresses that correspond with my hostname
        my_hostname = socket.getfqdn()
        addresses = socket.getaddrinfo(my_hostname, 4342, 0, 0, socket.SOL_UDP)
        listen_on = [ip_address(unicode(address[4][0]).split('%')[0]) for address in addresses]
        return listen_on

    def get_config_paths(self, config_file):
        # If the path is absolute then don't mess with it
        if os.path.isabs(config_file):
            return config_file

        # Construct a list of full paths to look for a given configuration file
        executable_file = os.path.realpath(sys.argv[0])
        executable_dir = os.path.dirname(executable_file)
        config_dir = os.path.join(executable_dir, '..', 'etc')

        paths = [os.path.join(os.path.sep, 'etc', 'lispd', config_file),
                 os.path.join(config_dir, 'lispd', config_file),
                 os.path.join('~', '.pylisp', 'lispd', config_file)]

        paths = map(os.path.expanduser, paths)
        paths = map(os.path.realpath, paths)

        return paths

    def get_potential_config_files(self):
        # Construct a list of potential configuration files.
        return self.get_config_paths('settings.py')

    def apply_config_files(self):
        # Execute potential configuration files in the current context so they
        # can manipulate it. Later files overrule previous settings.
        for filename in self.get_potential_config_files():
            try:
                # Import the settings under a dummy name
                mod = imp.load_source('PYLISP_USER_SETTINGS', filename)
                logger.info("Importing settings from {0}".format(filename))

                for setting in dir(mod):
                    if setting == setting.upper():
                        logger.debug('Loading setting {0}'.format(setting))
                        setting_value = getattr(mod, setting)
                        setattr(self, setting, setting_value)

                # Remove the dummy name from the system, otherwise the next config file might use its content
                # accidentally. The module content unfortunately hangs around...
                del sys.modules['PYLISP_USER_SETTINGS']

            except IOError, e:
                logger.debug("Could not import settings from {0}: {1}".format(filename, e))
            except:
                logger.exception("Error in config file {0}".format(filename))
                raise ConfigurationError("Error in config file {0}".format(filename))

        # Fix the configs where necessary
        self.fix_config()

    def fix_config(self):
        try:
            self.LISTEN_ON = [isinstance(addr, (IPv4Address, IPv6Address)) and addr or ip_address(unicode(addr))
                              for addr in self.LISTEN_ON]
        except:
            raise ConfigurationError("Invalid LISTEN_ON setting")

        try:
            for instance_id in self.INSTANCES:
                if not isinstance(instance_id, int):
                    raise ConfigurationError("INSTANCES must be a mapping with instance-id (int) as key")

                if afi.IPv4 not in self.INSTANCES[instance_id]:
                    # No IPv4 AFI
                    self.INSTANCES[instance_id][4] = ContainerNode(IPv4Network(u'0.0.0.0/0'))

                if afi.IPv6 not in self.INSTANCES[instance_id]:
                    # No IPv6 AFI
                    self.INSTANCES[instance_id][4] = ContainerNode(IPv6Network(u'::/0'))

                if (not isinstance(self.INSTANCES[instance_id][afi.IPv4], ContainerNode) or
                        self.INSTANCES[instance_id][afi.IPv4].prefix != IPv4Network(u'0.0.0.0/0')):
                    raise ConfigurationError("INSTANCES[{0}][afi.IPv4] must be a ContainerNode "
                                             "for 0.0.0.0/0".format(instance_id))

                if (not isinstance(self.INSTANCES[instance_id][afi.IPv6], ContainerNode) or
                        self.INSTANCES[instance_id][afi.IPv6].prefix != IPv6Network(u'::/0')):
                    raise ConfigurationError("INSTANCES[{0}][afi.IPv6] must be a ContainerNode "
                                             "for ::/0".format(instance_id))
        except (TypeError, IndexError, KeyError):
            raise ConfigurationError("Invalid INSTANCES setting")

        if not isinstance(self.PETR, (IPv4Address, IPv6Address, NoneType)):
            raise ConfigurationError("PETR must be an IPv4Address, an IPv6Address or None")

        if not isinstance(self.NATT, bool):
            raise ConfigurationError("NATT must be a boolena")

        if not isinstance(self.NFQUEUE_IPV4, (int, NoneType)):
            raise ConfigurationError("NFQUEUE_IPV4 must be an integer or None")

        if not isinstance(self.NFQUEUE_IPV6, (int, NoneType)):
            raise ConfigurationError("NFQUEUE_IPV6 must be an integer or None")


# Common configuration
config = Settings(only_defaults=True)
