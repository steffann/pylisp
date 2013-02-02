# # An example of a DDT Root config
# from pylisp.application.lispd.ddt.root_handler import DDTRootHandler
# handlers = [DDTRootHandler(root='ddt_root')]

from pylisp.application.lispd.map_server.handler import MapServerHandler
from pylisp.application.lispd.map_server.site import Site
from pylisp.utils.IPy_clone import IP
handlers = [MapServerHandler(sites=[Site(name='Demo 1',
                                         eid_prefixes=[IP('37.77.62.0/25')],
                                         authentication_key='BlaBlaBla'),
                                    Site(name='Demo 2',
                                         eid_prefixes=[IP('37.77.62.128/26'),
                                                       IP('37.77.62.224/27')],
                                         authentication_key='DummyBlaEtc'),
                                    Site(name='Steffann',
                                         eid_prefixes=[IP('2a00:8640:1::/48'),
                                                       IP('2a00:8640:1009::/48'),
                                                       IP('37.77.56.32/31'),
                                                       IP('37.77.56.64/26'),
                                                       IP('37.77.57.56/30')],
                                         authentication_key='SomeStrangePassword123')])]
