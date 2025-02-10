import logging

from .basics import set_op_mode
from ..decode import get_msg_ids

from .forwarding import _forward_getter, _forward_clearer
from . import connect as snmpconn

from .. import connection


@connection.add_method(snmpconn.SnmpConnection)
def get_ifms(target, snmp_args={}, **kwargs):
    """Get all entries int the Immediate Forward Table"""

    table_oid = "iso.0.15628.4.1.5"
    err_msg = "FAILED to get Immediate Forward (IFM) Table"

    return _forward_getter(target,snmp_args, table_oid, err_msg, **kwargs) 


@connection.add_method(snmpconn.SnmpConnection)
def set_ifm(target, msg_type, tx_ch, ifm_index=1, ifm_enable=1, tx_mode=0, snmp_args={}, **kwargs):
    """Set an entry in the Immediate Forward Table"""
    
    msg_ids = get_msg_ids(msg_type)

    oids = [("iso.0.15628.4.1.5.1.7.{}".format(ifm_index), "i", 4),
            ("iso.0.15628.4.1.5.1.5.{}".format(ifm_index), "i", tx_ch),
            ("iso.0.15628.4.1.5.1.4.{}".format(ifm_index), "i", tx_mode),
            ("iso.0.15628.4.1.5.1.2.{}".format(ifm_index), "x", '"{}"'.format(msg_ids["psid"])),
            ("iso.0.15628.4.1.5.1.3.{}".format(ifm_index), "i", msg_ids["msgid"]),
            ("iso.0.15628.4.1.5.1.6.{}".format(ifm_index), "i", ifm_enable)]
    err_msg = "FAILED to set Immediate Forward (IFM) Table entry"

    with snmpconn.SnmpChecker(target, snmp_args) as snmp:

        clear_ifm(target, ifm_index, snmp_args=snmp_args, **kwargs)

        op_set = set_op_mode(target, snmp_args, opmode=2, **kwargs)
        if int(list(op_set.values())[0]) != 2:
            raise Exception("FAILED to go to Standby")
        
        for oid in oids:
            try:
                set_cmd = snmp.set(oid[0], oid[1], oid[2], warn=True, **kwargs)
            except:
                logging.error(err_msg)
                raise
        
        op_set = set_op_mode(target, snmp_args, opmode=4, **kwargs)
        if int(list(op_set.values())[0]) != 4:
            raise Exception("FAILED to go to Operate")

        ifms_list = get_ifms(target, snmp_args=snmp_args, **kwargs)

        ifm_set = None
        for ifm in ifms_list:
            if int(ifm['index']) == int(ifm_index):
                ifm_set = ifm
    
    return ifm_set


@connection.add_method(snmpconn.SnmpConnection)
def clear_ifm(target, ifm_index:int, snmp_args={}, **kwargs):
    """Clear a previously set IFM table entry"""

    table_oid = "iso.0.15628.4.1.5.1.7" + ".{i}".format(i=ifm_index)
    err_msg = "FAILED: Could not clear FWD entry {ind}".format(ind=ifm_index)

    return _forward_clearer(target, snmp_args, table_oid, err_msg, **kwargs)
