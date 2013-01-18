'''
Created on 15 jan. 2013

@author: sander
'''
import os
import socket
import sys


class Settings(object):
    def __init__(self, verbose=0, only_defaults=False):
        # Set verbose
        self.verbose = verbose

        # Someone might want to know if there is more than the defaults
        self.only_defaults = only_defaults

        # Set the defaults
        self.set_defaults()

        if not only_defaults:
            # Apply the config
            self.apply_config_files()

    def set_defaults(self):
        self.listen_on = self.default_listen_on()

    def default_listen_on(self):
        # Listen to the IP addresses that correspond with my hostname
        my_hostname = socket.getfqdn()
        addresses = socket.getaddrinfo(my_hostname, 4342, 0, 0, socket.SOL_UDP)
        listen_on = [address[4] for address in addresses]
        return listen_on

    def get_potential_config_files(self):
        # Construct a list of potential configuration files. Files later in the
        # list are executed later and therefore override settings from previous
        # configuration files and the default settings.
        executable_file = os.path.realpath(sys.argv[0])
        executable_dir = os.path.dirname(executable_file)
        config_dir = os.path.join(executable_dir, '..', 'etc')

        return ['/etc/lispd/settings.py',
                os.path.join(config_dir, 'lispd_settings.py'),
                '~/.pylisp/lispd_settings.py']

    def apply_config_files(self):
        # Execute potential configuration files in the current context so they
        # can manupulate it
        for filename in self.get_potential_config_files():
            filename = os.path.expanduser(filename)
            filename = os.path.realpath(filename)

            try:
                exec(compile(open(filename).read(), filename, 'exec'),
                     self.__dict__)
                if self.verbose >= 1:
                    print("Imported settings from %s" % filename)
            except IOError, e:
                if self.verbose >= 2:
                    print("Could not import settings from %s: %s"
                          % (filename, e))


# Common configuration
config = Settings(only_defaults=True)
