import logging

from .basics import set_op_mode
from ..decode import get_msg_ids, hex_to_date, date_to_hex

from .forwarding import _forward_getter, _forward_clearer
from . import connect as snmpconn

from .. import connection


@connection.add_method(snmpconn.SnmpConnection)
def get_srms(target, snmp_args={}, **kwargs):
    """Get all entries int the Store and Repeat Table"""

    table_oid = "iso.0.15628.4.1.4"
    err_msg = "FAILED to get Store and Repeat (SRM) Table"

    return _forward_getter(target,snmp_args, table_oid, err_msg, **kwargs) 


@connection.add_method(snmpconn.SnmpConnection)
def set_srm(target, msg_type, tx_ch, payload, tx_mode=0, tx_interval=1000, srm_index=1, 
                srm_start="2017-10-07 23:34", srm_stop="07ea0a071722", srm_enable=1, snmp_args={}, **kwargs):
    """Set an entry in the Store and Repeat Table"""

    msg_ids = get_msg_ids(msg_type)

    srm_date_hex = []
    for srm in srm_start, srm_stop:
        try:
            srm_date_hex.append(date_to_hex(srm))
        except ValueError:
            hex_to_date(srm)
            srm_date_hex.append(srm)

    oids = [("iso.0.15628.4.1.4.1.11.{}".format(srm_index), "i", 4),
            ("iso.0.15628.4.1.4.1.5.{}".format(srm_index),  "i", tx_ch),
            ("iso.0.15628.4.1.4.1.4.{}".format(srm_index),  "i", tx_mode),
            ("iso.0.15628.4.1.4.1.2.{}".format(srm_index),  "x", '"{}"'.format(msg_ids["psid"])),
            ("iso.0.15628.4.1.4.1.3.{}".format(srm_index),  "i", msg_ids["msgid"]),
            ("iso.0.15628.4.1.4.1.6.{}".format(srm_index),  "i", tx_interval),
            ("iso.0.15628.4.1.4.1.7.{}".format(srm_index),  "x", '"{}"'.format(srm_date_hex[0])),
            ("iso.0.15628.4.1.4.1.8.{}".format(srm_index),  "x", '"{}"'.format(srm_date_hex[1])),
            ("iso.0.15628.4.1.4.1.9.{}".format(srm_index),  "x", '"{}"'.format(payload)),
            ("iso.0.15628.4.1.4.1.10.{}".format(srm_index), "i", srm_enable)]
    err_msg = "FAILED to set Store and Repeat Forward (SRM) Table entry"
    
    with snmpconn.SnmpChecker(target, snmp_args) as snmp:

        clear_srm(target, srm_index, snmp_args=snmp_args)

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

        srms_list = get_srms(target, snmp_args=snmp_args, **kwargs)

        srm_set = None
        for srm in srms_list:
            if int(srm['index']) == int(srm_index):
                srm_set = srm
    
    return srm_set


@connection.add_method(snmpconn.SnmpConnection)
def clear_srm(target, srm_index:int, snmp_args={}, **kwargs):
    """Clear a previously set SRM table entry"""

    table_oid = "iso.0.15628.4.1.4.1.11" + ".{i}".format(i=srm_index)
    err_msg = "FAILED: Could not clear SRM entry {ind}".format(ind=srm_index)

    return _forward_clearer(target, snmp_args, table_oid, err_msg, **kwargs)
