from pylisp.application.lispd.address_tree.container_node import ContainerNode
from pylisp.utils.auto_addresses import get_ipv4_address, get_ipv6_address
from pylisp.application.lispd.address_tree.authoritative_container_node import AuthoritativeContainerNode

LISTEN_ON = [get_ipv4_address('eth0'),
             get_ipv6_address('eth0')]

INSTANCES = {
    0: {
        1: ContainerNode(u'0.0.0.0/0', [
             AuthoritativeContainerNode('37.77.60.0/24', [
             ])
           ]),
        2: ContainerNode(u'::/0', [
             AuthoritativeContainerNode('2A00:8640:B000::/36', [
             ])
           ]),
       }
}
