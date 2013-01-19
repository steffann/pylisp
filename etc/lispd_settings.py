# Some examples of handlers
from IPy import IP
from pylisp.application.lispd.ddt_message_handler import LISPDDTMessageHandler
my_prefixes = [(IP('37.77.63.0/24'), None)]
handlers = [LISPDDTMessageHandler(data=my_prefixes)]
