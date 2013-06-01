'''
Created on 1 jun. 2013

@author: sander
'''
from pylisp.application.lispd.address_tree.container_node import ContainerNode
import logging


# Get the logger
logger = logging.getLogger(__name__)


class AuthoritativeContainerNode(ContainerNode):
    '''
    A ContainerNode that indicates that we are authoritative for this part of
    the address tree.
    '''
