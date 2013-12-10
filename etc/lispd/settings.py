from pylisp.application.lispd.address_tree.container_node import ContainerNode
from pylisp.utils.auto_addresses import get_ipv4_address, get_ipv6_address
from pylisp.application.lispd.address_tree.authoritative_container_node import AuthContainerNode
from pylisp.application.lispd.address_tree.map_server_node import MapServerNode

LISTEN_ON = [get_ipv4_address('vlan2'),
             get_ipv6_address('vlan2')]

PROCESS_DATA = False

INSTANCES = {0: {1: ContainerNode(prefix=u'0.0.0.0/0',
                                  children=[AuthContainerNode(prefix=u'37.77.56.0/21',
                                                              children=[MapServerNode(prefix=u'37.77.56.32/31', key='testtesttest'),
                                                                        MapServerNode(prefix=u'37.77.56.64/26', key='testtesttest'),
                                                                        MapServerNode(prefix=u'37.77.57.56/30', key='testtesttest')],
                                                              ddt_nodes=LISTEN_ON)]),
                 2: ContainerNode(prefix=u'::/0',
                                  children=[AuthContainerNode(prefix=u'2A00:8640::/32',
                                                              children=[MapServerNode(prefix=u'2A00:8640:1::/48', key='testtesttest'),
                                                                        MapServerNode(prefix=u'2A00:8640:1009::/48', key='testtesttest')],
                                                              ddt_nodes=LISTEN_ON)]),
                 }
             }
