import logging

from .basics import set_op_mode, _basic_getter
from . import connect as snmpconn

from .. import connection


@connection.add_method(snmpconn.SnmpConnection)
def get_dsrc_ch(target, snmp_args={}, **kwargs):
    """Get the DSRC channel(s) in use"""

    oids = ["iso.0.15628.4.1.12.1.4.1", "iso.0.15628.4.1.12.1.5.1", "iso.0.15628.4.1.12.1.4.2", "iso.0.15628.4.1.12.1.5.2"]
    err_msg = "FAILED: Get DSRC Channel"

    channels = {}
    for oid in oids:
        oid_out = _basic_getter(target, snmp_args, oid, err_msg, **kwargs)
        channels[list(oid_out.keys())[0]] = list(oid_out.values())[0]

    return channels


@connection.add_method(snmpconn.SnmpConnection)
def set_dsrc_ch(target, ch0, ch1, snmp_args={}, **kwargs):
    """Set the DSRC channel using the given snmp inputs. snmp_args is a dict that defines the snmp options"""

    oids = ["iso.0.15628.4.1.12.1.4.1", "iso.0.15628.4.1.12.1.5.1", "iso.0.15628.4.1.12.1.4.2", "iso.0.15628.4.1.12.1.5.2"]
    err_msg = "FAILED: Set DSRC Channel"

    with snmpconn.SnmpChecker(target, snmp_args) as snmp:

        errs = 0

        op_set = set_op_mode(target, snmp_args=snmp_args, opmode=2, **kwargs)
        if int(list(op_set.values())[0]) != 2:
            raise Exception("FAILED to go to Standby")

        # TODO: channels must be set as pair on Siemens not one at a time
        #   (eg snmpset $SNMP_ARGS 192.168.0.26 RSU-MIB::rsuDCMMode.1 i 0  RSU-MIB::rsuDCMCCH.1 i 180 RSU-MIB::rsuDCMSCH.1 i 180)
        for oid in oids:
            
            if oid.endswith("1"):
                try:
                    snmp.set(oid, "i", ch0, warn=True, **kwargs)
                except:
                    logging.error(err_msg)
                    raise
            
            elif oid.endswith("2"):
                try:
                    snmp.set(oid, "i", ch1, warn=True, **kwargs)
                except:
                    logging.error(err_msg)
                    raise
            
            else:
                pass   # Should never happen

        op_set = set_op_mode(target, snmp_args=snmp_args, opmode=4, **kwargs)
        if int(list(op_set.values())[0]) != 4:
            raise Exception("FAILED to go to Operate")

    # will return the new channel settings
    return get_dsrc_ch(target, snmp_args=snmp_args, **kwargs)
