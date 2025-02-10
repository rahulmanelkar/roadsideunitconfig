# Standard libraries
import logging
import re


class snmpTimeoutError(Exception):
    """raised when snmp times out"""
    pass

class snmpIndexError(Exception):
    "raised when a call is made to an invalid/empty MIB/OID index"
    pass

class snmpUnknownMibError(Exception):
    """raised when a call is made to an unknown MIB"""
    pass

class snmpUnknownOidError(Exception):
    """raised when a call is made to an unknown OID"""
    pass

class snmpInvalidValueError(Exception):
    """raised when an invalid value is used in an snmpset"""
    pass

class snmpTypeError(Exception):
    """raised when the wrong type is given to snmpset command"""
    pass

class snmpAuthenticationError(Exception):
    """raised when snmp can't authenticate"""
    pass

class snmpUsernameError(Exception):
    """raised when snmp detects an invalid user name"""
    pass

class snmpGeneralError(Exception):
    """raised when there's any other snmp error"""
    pass

class snmpOfflineError(Exception):
    """raised when the SnmpChecker has determined the SNMP connection is down"""
    pass


def snmp_exception_checker(snmp_out, log_msg=None, override=False):
    """run snmp commands through here to determine if an exception occurred. 
    If given a log_msg, write it before raising any Exception. Allows for log messages unique to any given function
    If override=True, then the error will NOT be logged. Useful for cases where an OID can be present or not depedning on whether it is set"""

    #  TODO: Spruce this up so that it can report the failed OID/MIB when available
    
    if snmp_out.return_code == 0 and "No Such Instance currently exists at this OID" in snmp_out.stdout and override is not True:
        # A missing/unknown MIB/OID index returns 0 and no stderr, because of course it does. Make a unique catch for this snmp design stupidity
        if log_msg is not None:
            logging.error(log_msg) 
        logging.error("OID/MIB index is either missing, empty, or invalid:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
        raise snmpIndexError("OID/MIB index is either missing, empty, or invalid")
    
    elif snmp_out.return_code == 0 and 'No Such Object available' in snmp_out.stdout and override is not True:
        # A missing/unknown OID returns 0 and no stderr, because of course it does. Make a unique catch for this snmp design stupidity
        if log_msg is not None:
            logging.error(log_msg)
        logging.error("No such OID:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
        raise snmpUnknownOidError(snmp_out.stdout)
    
    elif snmp_out.return_code !=0:
        if log_msg is not None:
            logging.error(log_msg) 

        if 'Timeout' in snmp_out.stderr:
            logging.error("snmp request timed out:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
            raise snmpTimeoutError("snmp request timed out")
        elif 'Unknown Object Identifier' in snmp_out.stderr:
            logging.error("MIB does not exist or is not configured:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
            raise snmpUnknownMibError("MIB does not exist or is not configured: {}".format(snmp_out.stderr))
        elif 'badValue' in snmp_out.stderr:
            logging.error("OID/MIB does not allow the given value:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
            raise snmpInvalidValueError("OID/MIB does not allow the given value")
        elif 'Bad variable type' in snmp_out.stderr:
            type_search = re.search("Type of attribute is (.*), not (.*)\)", snmp_out.stderr)
            logging.error("Bad variable type: Expected {exp}; Got {given}".format(exp=type_search.group(1), given=type_search.group(2)))
            raise snmpTypeError("Bad variable type: Expected {exp}; Got {given}".format(exp=type_search.group(1), given=type_search.group(2)))
        elif 'Authentication failure' in snmp_out.stderr:
            logging.error("snmp failed to Authenticate:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
            raise snmpAuthenticationError("snmp failed to Authenticate")
        elif 'Unknown user name' in snmp_out.stderr:
            logging.error("snmp does not recognize the given username:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
            raise snmpUsernameError("snmp does not recognize the given username")
        elif 'passphrase chosen is below the length requirements' in snmp_out.stderr:
            logging.error("snmp does not allow passwords shorter than 8 char:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
            raise snmpAuthenticationError("snmp passphrase is too short")            
        else:
            logging.error("UnkownError:\nCommand: {cmd}\nCode: {rtc}\nStdErr: {err}".format(cmd=snmp_out.command, err=snmp_out.stderr, rtc=snmp_out.return_code))
            raise snmpGeneralError(snmp_out.stderr)
    
    else:
        return snmp_out
