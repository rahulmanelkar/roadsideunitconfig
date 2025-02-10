from functools import wraps

import rsu_toolkit
from . import decode

class RsuConnection(object):
    """Create an overall class that contains both snmp and ssh objects in one.
    Function will determine which object to use using an object type checker function"""

    def __init__(self, ip, ssh_args={}, snmp_args={}, gateway=None, **kwargs):
        self.ip = ip

        if gateway is not None:
            ssh_args['gateway'] = gateway
            snmp_args['gateway'] = gateway

        self.gateway = gateway
    
        # _snmp_state has bits for [snmp_auth][rsu-mib][snmp_connect]. Current method will always flip the rsu-mib bit if any one MIB here fails
        # Meaning:
        # _snmp_state=0 is all good
        # _snmp_state=1 is sys MIBs down, RSU-MIB up
        # _snmp_state=2 is sys MIBs up, RSU-MIB down
        # _snmp_state=3 is all MIBs down
        # _snmp_state=4 is SNMP auth error
        try:
            self.snmp = rsu_toolkit.snmp.SnmpConnection(ip, **snmp_args)
            self._snmp_state = 0
        except rsu_toolkit.snmp.exceptions.snmpAuthenticationError:
            self.snmp = None
            self._snmp_state = 4
        except rsu_toolkit.snmp.exceptions.snmpUsernameError:
            self.snmp = None
            self._snmp_state = 4        
        except:
            # This will get set if the SNMP connection failed OR if it failed to get the system MIB in snmp.connect
            self.snmp = None
            self._snmp_state = 1
        # self.ssh = rsu_toolkit.ssh.Connection(ip, **ssh_args)

        # These will always fail if the first SNMP attempt fails due to pw issues
        if self._snmp_state !=4:
            try:
                self.sn = rsu_toolkit.snmp.get_id(self.snmp, hide=True)['RSU-MIB::rsuID.0']
                self._snmp_state = 0
            except IndexError:
                # This means it returned, but the output was blank
                self.sn = "BAD_RETURN"
            except:
                self.sn = "UNDEFINED"
                self._snmp_state = self._snmp_state | 2
            self.serial_number = self.sn

            try:
                self.mac = rsu_toolkit.snmp.get_mac(self.snmp, hide=True)['RSU-MIB::rsuContMacAddress.0']
            except:
                self.mac = "UNDEFINED"
                # Want SNMP state = rsu-mib bit set only if all RSU-MIBs fail, but need to preserve snmp_connect bit
                self._snmp_state = self._snmp_state & 3
        
            try:
                self.vendor = decode.mac_to_vendor(self.mac)
            except:
                self.vendor = "UNDEFINED"
        else:
            self.sn = "UNDEFINED"
            self.serial_number = self.sn
            self.mac = "UNDEFINED"
            self.vendor = "UNDEFINED"

        if self.vendor == 'kapsch':
            self.ssh = rsu_toolkit.ssh.kapsch.connect.KapschConnection(ip, **ssh_args)
        else:
            self.ssh = rsu_toolkit.ssh.Connection(ip, **ssh_args)


def add_method(cls):
    """Use this decorator function to make it possible to add functions to the class as methods"""
    
    def decorator(func):
        
        @wraps(func)
        def wrapper(self, *args, **kwargs): 
            return func(self, *args, **kwargs)
        setattr(cls, func.__name__, wrapper)
        # Note we are not binding func, but wrapper which accepts self but does exactly the same as func
        
        return func # returning func means func can still be used normally
    
    return decorator
