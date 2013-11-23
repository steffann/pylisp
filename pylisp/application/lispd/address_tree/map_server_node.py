'''
Created on 1 jun. 2013

@author: sander
'''
from pylisp.application.lispd.address_tree.base import AbstractNode
import logging


# Get the logger
logger = logging.getLogger(__name__)


class MapServerNode(AbstractNode):
    def handle_map_request(self, received_message, control_plane_sockets, data_plane_sockets):
        pass
