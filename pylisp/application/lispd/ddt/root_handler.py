'''
Created on 23 jan. 2013

@author: sander
'''
from pylisp.application.lispd import settings
from pylisp.application.lispd.ddt.message_handler import DDTMessageHandler
import logging
from IPy import IP
from pylisp.utils.ip_set import IPSet
from pylisp.utils.lcaf.instance_address import LCAFInstanceAddress


# Get the logger
logger = logging.getLogger(__name__)


class DDTRootHandler(DDTMessageHandler):
    def __init__(self, root):
        DDTMessageHandler.__init__(self)

        # Parse the zone file
        possible_root_files = settings.config.get_config_paths(root)
        for filename in possible_root_files:
            try:
                with open(filename) as root_file:
                    # Store the filename
                    self.root = filename

                    logger.info("Reading root data from %s" % filename)
                    self.read_root_file(root_file)
                break
            except IOError, e:
                logger.debug("Could not import root data from %s: %s",
                             filename, e)

    def read_root_file(self, root_file):
        # Start with an empty root
        self._root_instance_ids = {}

        line_nr = 0
        for line in root_file:
            line_nr += 1

            # Strip comments and white space
            line = line.split('#')[0]
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Split the line into its components: Instance-ID, AFI, EID prefix
            # and DDT node address the prefix is delegated to.
            parts = line.split()
            if len(parts) != 4:
                raise ValueError("DDT root file contains invalid record "
                                 "on line %d" % line_nr)

            instance_id, afi, eid_prefix, delegate_to = parts

            instance_id = int(instance_id)
            afi = int(afi)

            # Parse the EID prefix
            if afi == 0:
                eid_prefixes = [IP('0.0.0.0/0'),
                                IP('::/0')]
            elif afi == 1:
                eid_prefix = IP(eid_prefix)
                if eid_prefix.version() != 4:
                    raise ValueError("Invalid IP address %r for AFI 1 (IPv4) "
                                     "on line %d" % (eid_prefix, line_nr))
                eid_prefixes = [eid_prefix]
            elif afi == 2:
                eid_prefix = IP(eid_prefix)
                if eid_prefix.version() != 6:
                    raise ValueError("Invalid IP address %r for AFI 2 (IPv6) "
                                     "on line %d" % (eid_prefix, line_nr))
                eid_prefixes = [eid_prefix]
            else:
                raise ValueError("Invalid AFI %d on line %d" % (afi, line_nr))

            # Parse the delegated to address
            delegate_to = IP(delegate_to)

            # Do we know this instance ID?
            if instance_id not in self._root_instance_ids:
                # No: create a new one
                holes = IPSet([IP('0.0.0.0/0'), IP('::/0')])
                self._root_instance_ids[instance_id] = {'holes': holes,
                                                        'delegations': {}}

            # Add this data to the instance ID
            current_instance = self._root_instance_ids[instance_id]
            for eid_prefix in eid_prefixes:
                current_instance['holes'].discard(eid_prefix)

                # Add to the list of delegated-to addresses
                if eid_prefix not in current_instance['delegations']:
                    current_instance['delegations'][eid_prefix] = []

                current_instance['delegations'][eid_prefix].append(delegate_to)

    def is_authoritative(self, req_prefix):
        """
        The root is authoritative for everything!
        """
        return True

    def get_delegation(self, req_prefix):
        assert isinstance(req_prefix, LCAFInstanceAddress)

        # Do we know this instance ID?
        if req_prefix.instance_id not in self._root_instance_ids:
            # Whole instance ID is a hole
            if req_prefix.address.version() == 4:
                return IP('0.0.0.0/0'), []
            else:
                return IP('::/0'), []

        instance = self._root_instance_ids[req_prefix.instance_id]

        # Give back the addresses we delegate to
        for eid_prefix, delegate_to in instance['delegations'].iteritems():
            if req_prefix.address in eid_prefix:
                return LCAFInstanceAddress(instance_id=req_prefix.instance_id,
                                           address=eid_prefix), delegate_to

        # Nothing: hole
        for hole in instance['holes']:
            if req_prefix.address in hole:
                return LCAFInstanceAddress(instance_id=req_prefix.instance_id,
                                           address=hole), []

        # This should not happen!
        return req_prefix, []
