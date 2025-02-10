# Creates the reference to the Connection object
from .connection import Connection, SshChecker

# Import each vendor
from . import kapsch
from . import commsignia
