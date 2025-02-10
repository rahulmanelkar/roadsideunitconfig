import logging

from . import connect as snmpconn
from .. import decode

from .. import connection


@connection.add_method(snmpconn.SnmpConnection)
def get_fw_version(target, snmp_args={},**kwargs):
    """Get the FW version of the RSU"""

    oid = "iso.0.15628.4.1.17.2.0"
    err_msg = "FAILED: Get FW Version"

    return _basic_getter(target, snmp_args, oid, err_msg, **kwargs)


@connection.add_method(snmpconn.SnmpConnection)
def get_gps(target, snmp_args={}, **kwargs):
    """Get the GPS return string"""

    oid = "iso.0.15628.4.1.8.5.0"
    err_msg = "FAILED: Get GPS Output"

    return _basic_getter(target, snmp_args, oid, err_msg, **kwargs)


@connection.add_method(snmpconn.SnmpConnection)
def get_id(target, snmp_args={}, **kwargs):
    """Get the RSU ID string (SerialNumber is many cases)"""

    oid = "iso.0.15628.4.1.17.4.0"
    err_msg = "FAILED: Get ID/SN"

    return _basic_getter(target, snmp_args, oid, err_msg, **kwargs)


@connection.add_method(snmpconn.SnmpConnection)
def get_mac(target, snmp_args={}, **kwargs):
    """Get the MAC address of the RSU"""

    oid = "iso.0.15628.4.1.1.0"
    err_msg = "FAILED: Get RSU-MIB Version"

    return _basic_getter(target, snmp_args, oid, err_msg, **kwargs)


@connection.add_method(snmpconn.SnmpConnection)
def get_mib_version(target, snmp_args={}, **kwargs):
    """Get the version of the RSU-MIBs"""

    oid = "iso.0.15628.4.1.17.1.0"
    err_msg = "FAILED: Get RSU-MIB Version"

    return _basic_getter(target, snmp_args, oid, err_msg, **kwargs)


@connection.add_method(snmpconn.SnmpConnection)
def get_op_mode(target, snmp_args={}, **kwargs):
    """Get the RSU Mode (operating or standby)"""

    oid = "iso.0.15628.4.1.99.0"
    err_msg = "FAILED: Get Mode"
    
    return _basic_getter(target, snmp_args, oid, err_msg, **kwargs)


@connection.add_method(snmpconn.SnmpConnection)
def get_vendor(target, snmp_args={}, **kwargs):
    """Get the vendor string"""

    oid = "iso.0.15628.4.1.17.5.0"
    err_msg = "FAILED: Get Manufacturer"

    return _basic_getter(target, snmp_args, oid, err_msg, **kwargs)


@connection.add_method(snmpconn.SnmpConnection)
def set_op_mode(target, snmp_args={}, opmode=4, **kwargs):
    """Set rsuMode to standy or operate"""

    oid = "iso.0.15628.4.1.99.0"
    err_msg = "FAILED: Set Mode to {mode}".format(mode=opmode)
    
    with snmpconn.SnmpChecker(target, snmp_args) as snmp:
    
        if not (int(opmode) == 2 or int(opmode) == 4 or int(opmode) == 16):
            logging.error("UNSUPPORTED VALUE! Opmode must be INTEGER = 2, 4, or 16.")
            raise ValueError("Opmode must be INTEGER = 2 or 4 or 16")

        try:
            mode_set = snmp.set(oid, "i", opmode, warn=True, **kwargs)
        except:
            logging.error(err_msg)
            raise

    return get_op_mode(target, snmp_args=snmp_args, **kwargs)


def _basic_getter(tgt, snmp_args, oid, err_msg, **kwargs):
    """Basic logic used by the get functions"""

    with snmpconn.SnmpChecker(tgt, snmp_args) as snmp:
        try:
            oid_get = snmp.get(oid, warn=True, **kwargs)
        except:
            logging.error(err_msg)
            raise
        
        oid_out = {decode.oid_to_mib(oid): oid_get.stdout.split("=")[1].split(":")[1].strip().strip('"')}

    return oid_out


get_sn = get_id