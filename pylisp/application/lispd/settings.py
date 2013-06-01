'''
Created on 15 jan. 2013

@author: sander
'''
import imp
import logging
import multiprocessing.dummy as mp
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

        # Set the defaults
        self.set_defaults()

        if not self.only_defaults:
            # Apply the config
            self.apply_config_files()

    def set_defaults(self):
        # A list of tuples containing an IP address and a port number
        self.LISTEN_ON = self.default_listen_on()

        # A list of instances. The key is the instance-id, the value a dict
        # of AFI-ids pointing to ContainerNodes.
        self.INSTANCES = {}

        # Set the default number of threads
        self.THREAD_POOL_SIZE = None
        try:
            self.THREAD_POOL_SIZE = mp.cpu_count() * 10
        except NotImplementedError:
            logger.warning('Can not determine the number of CPUs, you might'
                           ' want to configure the THREAD_POOL_SIZE manually')

    def default_listen_on(self):
        # Listen to the IP addresses that correspond with my hostname
        my_hostname = socket.getfqdn()
        addresses = socket.getaddrinfo(my_hostname, 4342, 0, 0, socket.SOL_UDP)
        listen_on = [address[4] for address in addresses]
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
                mod = imp.load_source('DUMMY_MODULE_NAME', filename)
                logger.info("Importing settings from {0}".format(filename))

                for setting in dir(mod):
                    if setting == setting.upper():
                        logger.debug('Loading setting {0}'.format(setting))
                        setting_value = getattr(mod, setting)
                        setattr(self, setting, setting_value)

                # Remove the dummy name from the system, otherwise the next config file might use its content
                # accidentally. The module content unfortunately hangs around...
                del sys.modules['DUMMY_MODULE_NAME']

            except (IOError, ImportError), e:
                logger.debug("Could not import settings from {0}: {1}".format(filename, e))
            except:
                logger.exception("Error in config file {0}".format(filename))
                raise

# Common configuration
config = Settings(only_defaults=True)
