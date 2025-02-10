# Standard libraries
import logging

# Non-standard libraries
import invoke
from . import exceptions as snmpexceptions
from ..connection import RsuConnection


class SnmpConnection(object):
    """Create an snmp object in order to manage inputs and returns from snmp requests"""

    def __init__(self, ip, username="rwUser", authkey="herbertherbert", authprotocol="SHA", 
                    passphrase="herbertherbert", encryption="AES", level="authpriv", gateway=None, **kwargs):

        self.snmp_arg_str = "-v 3 -u {username} -l {level} -a {authprotocol} -A {authkey} -x {encryption} -X {passphrase} {ip} ".format(
                                username=username, level=level, authprotocol=authprotocol, 
                                authkey=authkey, encryption=encryption, passphrase=passphrase, ip=ip)
        self.ip = ip
        self.user = username
        self.authprotocol = authprotocol
        self.encryption = encryption
        self.gateway = gateway
        self.level = level
        # TODO: Figure out if there's some secret's manager type way to prevent these from being accessible
        self.authkey = authkey
        self.passphrase = passphrase
        
        if gateway is not None:
            self.conn = gateway
        else:
            self.conn = invoke
        
        # Poll the system description OID (should be standard) to see if anything is there
        try:
            self.system = self.get("1.3.6.1.2.1.1.1.0", warn=True, hide=True).stdout
        except:
            logging.error("SNMP_CONN: Failed polling snmp client.")
            self.system = None
            raise

   
    def bulkwalk(self, oid, timeout=1, override=False, **kwargs):
        """Run a snmpbulkwalk command with all the correct arguments. 
        Setting override=True will suppress any snmpIndexError or snmpUnknownOidError. Useful for cases where it is valid for an OID to be missing if not set"""

        cmd = self.conn.run("snmpbulkwalk -t{to} {snmp_args} {oid}".format(to=timeout, snmp_args=self.snmp_arg_str, oid=oid), **kwargs)

        checked = snmpexceptions.snmp_exception_checker(cmd, override=override)

        return checked
    
    
    def get(self, oid, timeout=1, override=False, **kwargs):
        """Run a snmpget command with all the correct arguments.
        Setting override=True will suppress any snmpIndexError or snmpUnknownOidError. Useful for cases where it is valid for an OID to be missing if not set"""

        cmd = self.conn.run("snmpget -t{to} {snmp_args} {oid}".format(to=timeout, snmp_args=self.snmp_arg_str, oid=oid), **kwargs)

        checked = snmpexceptions.snmp_exception_checker(cmd, override=override)

        return checked

    
    def set(self, oid, oidtype, oidvalue, timeout=1, **kwargs):
        """Run a snmpset command with all the correct arguments"""

        cmd = self.conn.run("snmpset -t{to} {snmp_args} {oid} {oidtype} {oidvalue}".format(to=timeout, snmp_args=self.snmp_arg_str, oid=oid, 
                                                                                            oidtype=oidtype, oidvalue=oidvalue), **kwargs)

        checked = snmpexceptions.snmp_exception_checker(cmd)

        return checked

    def _usm(self, op, cur_val, new_val=None, timeout=1, **kwargs):
        """Used as part of setting and altering user profiles"""

        if op == "delete":
            cmd = self.conn.run("snmpusm -t{to} {snmp_args} {op} {del_user}".format(to=timeout, snmp_args=self.snmp_arg_str, op=op,
                                                                                    del_user=cur_val), **kwargs)
        elif op == "create":
            if new_val == None:
                raise TypeError("new_val= must have a value that is not None")
            cmd = self.conn.run("snmpusm -t{to} {snmp_args} {op} {new_user} {o_user}".format(to=timeout, snmp_args=self.snmp_arg_str, op=op,
                                                                                             new_user=new_val, o_user=cur_val), **kwargs)
        else:
            if new_val == None:
                raise TypeError("new_val= must have a value that is not None")
            cmd = self.conn.run("snmpusm -t{to} {snmp_args} {op} {o_val} {new_val}".format(to=timeout, snmp_args=self.snmp_arg_str, op=op,
                                                                                             new_val=new_val, o_val=cur_val), **kwargs)

        checked = snmpexceptions.snmp_exception_checker(cmd)

        return checked

    def _vacm(self, cmd_string, **kwargs):
        """Used as part of setting and altering user profiles"""

        cmd = self.conn.run("snmpvacm {ip} {c}".format(ip=self.ip, c=cmd_string), **kwargs)

        checked = snmpexceptions.snmp_exception_checker(cmd)

        return checked


class SnmpChecker():
    """Check the input type, and do something with it"""

    def __init__(self, tgt, snmp_args) -> None:
        self.tgt = tgt
        self.snmp_args = snmp_args 
        
    def __enter__(self) -> SnmpConnection:
        if type(self.tgt) is str:
            self.snmp = SnmpConnection(self.tgt, **self.snmp_args)
        elif isinstance(self.tgt, SnmpConnection):
            self.snmp = self.tgt
        elif isinstance(self.tgt, RsuConnection):
            if  self.tgt._snmp_state >= 4 :
                logging.error(f"SNMP: SNMP auth errors were detected: State = {self.tgt._snmp_state}")
                raise snmpexceptions.snmpAuthenticationError
            elif self.tgt._snmp_state != 0 :
                # This occurs if the connection was tried and failed or RSU-MIBs are down
                logging.error(f"SNMP: SNMP connection errors were detected: State = {self.tgt._snmp_state}")
                raise snmpexceptions.snmpOfflineError
            else:
                self.snmp = self.tgt.snmp
        elif self.tgt is None:
            logging.error(f"SNMP: Can't use this object type to connect: {type(self.tgt)}")
            raise snmpexceptions.snmpOfflineError
        else:
            logging.error(f"SNMP: Can't use this object type to connect: {type(self.tgt)}")
            raise TypeError(f"SNMP: Can't use this object type to connect: {type(self.tgt)}")

        return self.snmp

    def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
        # TODO: This can be useful to catch a failed snmp connection gracefully I think...
        # print(exc_type)
        # print(exc_value)
        # print(exc_traceback)
        pass

