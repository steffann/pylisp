from pylisp.application.lispd.address_tree.container_node import ContainerNode
from pylisp.utils.auto_addresses import get_ipv4_address, get_ipv6_address
from pylisp.application.lispd.address_tree.authoritative_container_node import AuthContainerNode
from pylisp.application.lispd.address_tree.map_server_node import MapServerNode

LISTEN_ON = [get_ipv4_address('eth0'),
             get_ipv6_address('eth0')]

INSTANCES = {0: {1: ContainerNode(prefix=u'0.0.0.0/0',
                                  children=[AuthContainerNode(prefix='37.77.60.0/24',
                                                              children=[MapServerNode(prefix='37.77.60.0/24',
                                                                                      )],
                                                              ddt_nodes=LISTEN_ON)]),
                 2: ContainerNode(prefix=u'::/0',
                                  children=[AuthContainerNode(prefix='2A00:8640:B000::/36',
                                                              children=[],
                                                              ddt_nodes=LISTEN_ON)]),
                 }
             }
