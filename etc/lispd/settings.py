# Load the DDT-Root
from pylisp.application.lispd.utils.ddt_root_loader import load_ddt_root
import os.path

INSTANCES = load_ddt_root(os.path.join(os.path.dirname(__file__), 'ddt_root'))
