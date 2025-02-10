import logging

from .basics import set_op_mode
from ..decode import get_msg_ids, hex_to_date, date_to_hex, ip_to_hex, oid_to_mib
from . import connect as snmpconn
from . import exceptions as snmpexceptions
from .. import connection


@connection.add_method(snmpconn.SnmpConnection)
def get_fwds(target, snmp_args={}, **kwargs):
    """Get the currently set forwarding info"""

    table_oid = "iso.0.15628.4.1.7"
    err_msg = "FAILED to get Forward Table"

    return _forward_getter(target,snmp_args, table_oid, err_msg, **kwargs)

@connection.add_method(snmpconn.SnmpConnection)
def set_fwd(target, msg_type:str, fwd_ip:str, fwd_port:int, fwd_index:int=1, fwd_protocol="udp",
            fwd_interval=1, fwd_start="2017-10-07 23:34", fwd_stop="07ea0a071722", fwd_enable=1, snmp_args={}, **kwargs):
    """Set an entry in the forwarding table. Time format is either RSU hex OR long-iso 'yyyy-mm-dd hh:mm'. """

    msg_ids = get_msg_ids(msg_type)
    fwd_proto = {"tcp": 1, "udp": 2}

    # Conver IPv4 to hex
    hex_ip_fwd = ip_to_hex(fwd_ip)

    # Make sure the dates are in RSU hex, convert if not
    fwd_date_hex =[]
    for fwd in fwd_start, fwd_stop:
        try:
            fwd_date_hex.append(date_to_hex(fwd))
        except ValueError:
            hex_to_date(fwd)
            fwd_date_hex.append(fwd)
    
    oids = [("iso.0.15628.4.1.7.1.11.{}".format(fwd_index), "i", 4),
            ("iso.0.15628.4.1.7.1.2.{}".format(fwd_index),  "x", '"{}"'.format(msg_ids["psid"])),
            ("iso.0.15628.4.1.7.1.3.{}".format(fwd_index),  "x", '"{}"'.format(hex_ip_fwd)),
            ("iso.0.15628.4.1.7.1.4.{}".format(fwd_index),  "i", fwd_port),
            ("iso.0.15628.4.1.7.1.5.{}".format(fwd_index),  "i", fwd_proto[fwd_protocol]),
            ("iso.0.15628.4.1.7.1.6.{}".format(fwd_index),  "i", -100),
            ("iso.0.15628.4.1.7.1.7.{}".format(fwd_index),  "i", fwd_interval),
            ("iso.0.15628.4.1.7.1.8.{}".format(fwd_index),  "x", '"{}"'.format(fwd_date_hex[0])),
            ("iso.0.15628.4.1.7.1.9.{}".format(fwd_index),  "x", '"{}"'.format(fwd_date_hex[1])),
            ("iso.0.15628.4.1.7.1.10.{}".format(fwd_index), "i", fwd_enable)]
    err_msg = "FAILED to set Forward Table"
    
    with snmpconn.SnmpChecker(target, snmp_args) as snmp:

        clear_fwd(target, fwd_index, snmp_args=snmp_args, **kwargs)

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

        fwds_list = get_fwds(target, snmp_args=snmp_args, **kwargs)

        fwd_set = None
        for fwd in fwds_list:
            if int(fwd['index']) == int(fwd_index):
                fwd_set = fwd
    
    return fwd_set


@connection.add_method(snmpconn.SnmpConnection)
def clear_fwd(target, table_index:int, snmp_args={}, **kwargs):
    """Clear a saved forward"""
    
    table_oid = "iso.0.15628.4.1.7.1.11" + ".{i}".format(i=table_index)
    err_msg = "FAILED: Could not clear FWD entry {ind}".format(ind=table_index)

    return _forward_clearer(target, snmp_args, table_oid, err_msg, **kwargs)


def _forward_getter(tgt, snmp_args, oid, err_msg, hide=True, **kwargs):
    """Function for getting forwards from IFM, SRM, and Fwd Table"""

    with snmpconn.SnmpChecker(tgt, snmp_args) as snmp:

        try:
            table_out = snmp.bulkwalk(oid, override=True, warn=True, hide=hide, **kwargs)
        except snmpexceptions.snmpUnknownOidError:
            # TODO: The exception handler still logs this as an error, figure what to do about that
            return None
        except:
            logging.error(err_msg)
            raise

        split_list = []
        for i,fwd_entry in enumerate(table_out.stdout.split('\niso')[:-1]):
            # Have to split on '\niso', otherwise some long payload values run into multilines and break this
            # However, splitting on anything removes what it was split by and Python seems to have no method for this. So need to re-add the needed 'iso' portion
            # However, 'iso' is not removed from first item in list, since it is 'iso' not '\niso'
            if i > 0:
                fwd_entry = 'iso' + str(fwd_entry)

            oid = fwd_entry.split("=")[0].strip()
            oid_val = fwd_entry.split("=")[1].split(":")[1].strip().strip('"').replace('\n', '')
            table_slot = fwd_entry.split(".")[7]
            entry_index = fwd_entry.split(".")[8].split('=')[0].strip()
            
            fwd_tup = (oid, oid_val, table_slot, entry_index)
            split_list.append(fwd_tup)

        sorted_fwd = sorted(split_list, key=lambda x: (int(x[3]), int(x[2])))

        i = 0
        fwds_list = []
        fwd_dict = {}
        for fwd in sorted_fwd:

            # This works by exploiting Python dict behavior: fwd_dict is modified until it is re-initialized in the else
            #  Ie even though 1st loop starts by append a one item dict, each loop expands that in the list dict, not a new one
            if i == fwd[3]:
                fwd_dict[oid_to_mib(fwd[0]).split(".")[0]] = fwd[1]
            else:
                # Blanking the dict here essential.
                #  This stops the modification of the previous dictionary, and Python now treats this as a new unrelated dict
                fwd_dict = {}
                fwd_dict['index'] = fwd[3]
                fwd_dict[oid_to_mib(fwd[0]).split(".")[0]] = fwd[1]
                fwds_list.append(fwd_dict)
                i = fwd[3]

    return fwds_list


def _forward_clearer(tgt, snmp_args, oid_and_ind, err_msg, **kwargs):
    """Basic fuctcion for clearing a forward from fwd table, SRM, or IFM."""

    with snmpconn.SnmpChecker(tgt, snmp_args) as snmp:

        op_set = set_op_mode(tgt, snmp_args=snmp_args, opmode=2, **kwargs)
        if int(list(op_set.values())[0]) != 2:
            raise Exception("FAILED to go to Standby")
        
        try:
            clr_out = snmp.set(oid_and_ind, "i", 6, **kwargs)
        except:
            logging.error(err_msg)
            raise

        op_set = set_op_mode(tgt, snmp_args=snmp_args, opmode=4, **kwargs)
        if int(list(op_set.values())[0]) != 4:
            raise Exception("FAILED to go to Operate")

    return 0
