import re


_known_msgs = { "TIM" : {   "psid"  : "8003",
                            "msgid" : 31},
                "SPAT": {   "psid"  : "8002",
                            "msgid" : 19},
                "MAP" : {   "psid"  : "E0000017",
                            "msgid" : 18},
                "SSM" : {   "psid"  : "E0000015",
                            "msgid" : 30},
                "BSM" : {   "psid"  : "20",
                            "msgid" : 20},
                "SRM" : {   "psid"  : "E0000016",
                            "msgid" : 29},
                "RTCM": {   "psid"  : "8000",
                            "msgid" : 28},
                "PSM": {   "psid"  : "27",
                            "msgid" : 32}
              }

_vendors = {'00E06A' : 'kapsch',
            '04E548' : 'siemens',   # Online decoders decode this as Cohda
            '4C93A6' : 'commsignia',
            'F61632' : 'danlaw'}

_ouis = {y:x for x,y in _vendors.items()}

# OID <-> RSU-MIB::name dicts are at bottom of file due to ridiculous length


def get_msg_ids(msg):
    """Given a recognized message type, return the PSID and MsgID"""

    known_msgs = _known_msgs

    if msg.upper() not in known_msgs.keys():
        raise ValueError("Unknown Message Type: Valid Types: {}".format(known_msgs.keys()))
    else:
        return known_msgs[msg.upper()]


def get_msg_type(psid:str=None, msgid:int=None):
    """Given a psid or msgid, return the associated message type. If given both, also verify that they both correspond to the same type"""
    
    known_msgs = _known_msgs

    if psid is None and msgid is None:
        raise TypeError("Requires at least 1 parameter: Input a value for either psid= or msgid= or both")

    elif psid is None and msgid is not None:
        for msg_type, msg_values in known_msgs.items():
            if msg_values["msgid"] == int(msgid):
                return msg_type
            else:
                continue
        else:
            raise ValueError("No matching MsgId found in _known_msgs: {}".format(msgid))

    elif psid is not None and msgid is None:
        for msg_type, msg_values in known_msgs.items():
            if msg_values["psid"] == str(psid).upper().replace(' ', ''):
                return msg_type
            else:
                continue
        else:
            raise ValueError("No matching PSID found in _known_mgs: {}".format(psid))

    elif psid is not None and msgid is not None:
        format_psid = str(psid).upper().replace(' ', '')
        for msg_type, msg_values in known_msgs.items():

            if msg_values["psid"] == format_psid and msg_values["msgid"] == int(msgid):
                return msg_type
            elif (msg_values["psid"] == format_psid and msg_values["msgid"] != int(msgid)) or (msg_values["psid"] != format_psid and msg_values["msgid"] == int(msgid)):
                 raise ValueError("PSID and MsgId do not correspond to same message type")
            else:
                continue

        else:
            raise ValueError("No matches found for PSID and/or MsgId found in _known_msgs")

    else:
        # I don't think there's any way to get here
        raise Exception("I have no idea how we got here")
    

def hex_to_date(hex_date):
    """Take the hex format for datetime used by RSU and convert it to a standard date time format"""

    # remove spaces if it has been input is using spaces
    hex_date = hex_date.replace(' ', '')

    # remove 0x if input is prefixed with 0x
    if hex_date.startswith("0x"):
        hex_date = hex_date[2:]

    if len(hex_date) != 12:
        raise ValueError("Expected 6 byte (12char) hex string: Got {}char".format(len(hex_date)))
    
    datetime_int = {"year"  : int(hex_date[0:4], 16),
                    "month" : int(hex_date[4:6], 16),
                    "day"   : int(hex_date[6:8], 16),
                    "hour"  : int(hex_date[8:10], 16),
                    "minute": int(hex_date[10:12], 16)}

    return datetime_int


def date_to_hex(datetime_str):
    """If given a parsable long-iso style string, convert that string to RSU hex format. 
    Date order should be yyyy, mm, dd in that order. Dates can be split with /, - , or left unseparated"""
    
    # TODO: Improve detection if date is mmddyyyy instead of yyyymmdd

    if "T" in datetime_str:
        date_str, time_str = datetime_str.split("T")
    else:
        date_str, time_str = datetime_str.split(" ")

    if '-' in date_str:
        date_split = date_str.split("-")
    elif '/' in date_str:
        date_split = date_str.split("/")
    else:
        date_split = [date_str[0:4], date_str[4:6], date_str[6:8]]

    if ":" in time_str:
        time_split = time_str.split(":")
    else:
        time_split = [time_str[0:2], time_str[2:4]]

    if len(date_split[0]) == 2:
        # Assume user input mm/dd/yyyy or mm-dd-yyyy
        year = date_split[2]
        month = date_split[0]
        day = date_split[1]
    else:
        # Assume user input yyyy/mm/dd or yyyy-mm-dd
        year = date_split[0]
        month = date_split[1]
        day = date_split[2]
    
    hex_dt = "{year:04x}{month:02x}{day:02x}{hour:02x}{minute:02x}".format(year=int(year), month=int(month), day=int(day), 
                                                                           hour=int(time_split[0]), minute=int(time_split[1]))

    return hex_dt


def ip_to_hex(ip):
    """Convert an ipv4 address to RSU hex format"""
    # TODO: Add ipv6 support

    if len(ip.split('.')) != 4:
        raise ValueError("Could not parse IP address. Must be IPv4 (x.x.x.x)")

    hex_ip = "00000000000000000000ffff"

    for ip_part in ip.split('.'):

        if 0 <= int(ip_part) < 256: 
            hex_ip = hex_ip + "{:02x}".format(int(ip_part))
        else:
            raise ValueError("Invalid IP address, value out of range: {}".format(ip_part))

    return hex_ip


def hex_to_ip(hex_ip):
    """Convert an RSU hex IP address to ipv4"""

    # replace whitespaces if input included whitespace
    hex_ip = hex_ip.replace(' ', '')

    # trim leading 0x if input included leading 0x
    hex_ip = hex_ip.replace('0x', '')
    # if hex_ip.startswith('0x'):
    #     hex_ip = hex_ip[2:]

    if hex_ip.lower().startswith("00000000000000000000ffff") or len(hex_ip) == 8:

        # trim the ipv6 header if it was present
        hex_ip = hex_ip.lower().replace('00000000000000000000ffff', '')

        ipv4 = f"{int(hex_ip[0:2],16)}.{int(hex_ip[2:4],16)}.{int(hex_ip[4:6],16)}.{int(hex_ip[6:8],16)}"
    
    else:
        raise ValueError("Does not appear to be IPv4. No conversion possible")

    return ipv4
    

def mib_to_oid(mib):
    """Given a RSU-MIB name, return the corresponding OID iso.0.15628.4.x.x..."""

    # Make it work with or withou RSU-MIB:: prepended
    if mib.startswith("RSU-MIB::"):
        mib_str = mib[9:]
    else:
        mib_str = mib
    
    # Make it work with or without an attached index value
    mib_index = None
    mib_regex = re.search("(.*).(\d+)$", mib_str)
    if mib_regex:
        mib_str = mib_regex.group(1)
        mib_index = mib_regex.group(2)
    
    try:
        # TODO: Decide if I want it to be case insensitive - MIBs are case sensitive so probably not
        if mib_index is None:
            return _rsu_mibs[mib_str]
        else:
            return "{s}.{i}".format(s=_rsu_mibs[mib_str], i=mib_index)
    except KeyError:
        raise KeyError("Unknown/unsupported MIB name: {}".format(mib_str))


def oid_to_mib(oid):
    """Given a RSU-MIB name, return the corresponding OID iso.0.15628.4.x.x..."""

    if oid.startswith("1.0.15628.4"):
        oid_str = oid.replace("1.0.15628.4", "iso.0.15628.4")
    else:
        oid_str = oid
    
    # TODO: this try ecept logic works to catch an index and translate correctly, but it seems messy...
    try:
        return "RSU-MIB::{}".format(_rsu_oids[oid_str])
    except KeyError:
        oid_index = None
        oid_regex = re.findall("(.*)\.(\d+)$", oid_str)
        if oid_regex:
            oid_str = oid_regex[0][0]
            oid_index = oid_regex[0][1]
        try:
            return "RSU-MIB::{s}.{i}".format(s=_rsu_oids[oid_str], i=oid_index)
        except KeyError:
            raise KeyError("Unknown/unsupported OID value: {}".format(oid))


def mac_to_vendor(mac_addr):
    """Given a MAC address, decode it to the vendor. 
    Use this instead of SNMP vendor field because 1) Some vendors don't support it yet, and 
    2) some vendors report differently based on version. This is a more fool proof method"""

    # MAC may have form 'xx:xx:xx' or 'xx xx xx'; account for both
    mac_addr = mac_addr.replace(' ', '')
    mac_addr = mac_addr.replace(':', '')
    mac_addr = mac_addr.upper()


    # vendors = {'00E06A' : 'kapsch',
    #            '04E548' : 'siemens',   # Online decoders decode this as Cohda
    #            '4C93A6' : 'commsignia',
    #            'F61632' : 'danlaw'}

    try:
        vendor = _vendors[mac_addr[:6]]
    except KeyError:
        # Warn and continue so that user can manually specify a vendor (once feature is complete)
        vendor = "unknown"

    return vendor


def vendor_to_oui(vendor:str):
    """Given a vendor/manufacturer as a string, return the OUI associated with it"""

    try:
        oui = _ouis[vendor.lower()]
    except KeyError:
        oui = "unknown"

    return oui


_rsu_mibs = {"rsuContMacAddress"               : "iso.0.15628.4.1.1",
             "rsuAltMacAddress"                : "iso.0.15628.4.1.2",
             "rsuGPSStatus"                    : "iso.0.15628.4.1.3",
             "rsuSRMStatusEntry"               : "iso.0.15628.4.1.4.1",
             "rsuSRMIndex"                     : "iso.0.15628.4.1.4.1.1",
             "rsuSRMPsid"                      : "iso.0.15628.4.1.4.1.2",
             "rsuSRMDsrcMsgId"                 : "iso.0.15628.4.1.4.1.3",
             "rsuSRMTxMode"                    : "iso.0.15628.4.1.4.1.4",
             "rsuSRMTxChannel"                 : "iso.0.15628.4.1.4.1.5",
             "rsuSRMTxInterval"                : "iso.0.15628.4.1.4.1.6",
             "rsuSRMDeliveryStart"             : "iso.0.15628.4.1.4.1.7",
             "rsuSRMDeliveryStop"              : "iso.0.15628.4.1.4.1.8",
             "rsuSRMPayload"                   : "iso.0.15628.4.1.4.1.9",
             "rsuSRMEnable"                    : "iso.0.15628.4.1.4.1.10",
             "rsuSRMStatus"                    : "iso.0.15628.4.1.4.1.11",
             "rsuIFMStatusEntry"               : "iso.0.15628.4.1.5.1",
             "rsuIFMIndex"                     : "iso.0.15628.4.1.5.1.1",
             "rsuIFMPsid"                      : "iso.0.15628.4.1.5.1.2",
             "rsuIFMDsrcMsgId"                 : "iso.0.15628.4.1.5.1.3",
             "rsuIFMTxMode"                    : "iso.0.15628.4.1.5.1.4",
             "rsuIFMTxChannel"                 : "iso.0.15628.4.1.5.1.5",
             "rsuIFMEnable"                    : "iso.0.15628.4.1.5.1.6",
             "rsuIFMStatus"                    : "iso.0.15628.4.1.5.1.7",
             "rsuSysObjectID"                  : "iso.0.15628.4.1.6",
             "rsuDsrcForwardEntry"             : "iso.0.15628.4.1.7.1",
             "rsuDsrcForwardIndex"             : "iso.0.15628.4.1.7.1.1",
             "rsuDsrcFwdPsid"                  : "iso.0.15628.4.1.7.1.2",
             "rsuDsrcFwdDestIpAddr"            : "iso.0.15628.4.1.7.1.3",
             "rsuDsrcFwdDestPort"              : "iso.0.15628.4.1.7.1.4",
             "rsuDsrcFwdProtocol"              : "iso.0.15628.4.1.7.1.5",
             "rsuDsrcFwdRssi"                  : "iso.0.15628.4.1.7.1.6",
             "rsuDsrcFwdMsgInterval"           : "iso.0.15628.4.1.7.1.7",
             "rsuDsrcFwdDeliveryStart"         : "iso.0.15628.4.1.7.1.8",
             "rsuDsrcFwdDeliveryStop"          : "iso.0.15628.4.1.7.1.9",
             "rsuDsrcFwdEnable"                : "iso.0.15628.4.1.7.1.10",
             "rsuDsrcFwdStatus"                : "iso.0.15628.4.1.7.1.11",
             "rsuGpsOutput"                    : "iso.0.15628.4.1.8",
             "rsuGpsOutputPort"                : "iso.0.15628.4.1.8.1",
             "rsuGpsOutputAddress"             : "iso.0.15628.4.1.8.2",
             "rsuGpsOutputInterface"           : "iso.0.15628.4.1.8.3",
             "rsuGpsOutputInterval"            : "iso.0.15628.4.1.8.4",
             "rsuGpsOutputString"              : "iso.0.15628.4.1.8.5",
             "rsuGpsRefLat"                    : "iso.0.15628.4.1.8.6",
             "rsuGpsRefLon"                    : "iso.0.15628.4.1.8.7",
             "rsuGpsRefElv"                    : "iso.0.15628.4.1.8.8",
             "rsuGpsMaxDeviation"              : "iso.0.15628.4.1.8.9",
             "rsuInterfaceLogTable"            : "iso.0.15628.4.1.9",
             "rsuInterfaceLogEntry"            : "iso.0.15628.4.1.9.1",
             "rsuIfaceLogIndex"                : "iso.0.15628.4.1.9.1.1",
             "rsuIfaceGenerate"                : "iso.0.15628.4.1.9.1.2",
             "rsuIfaceMaxFileSize"             : "iso.0.15628.4.1.9.1.3",
             "rsuIfaceMaxFileTime"             : "iso.0.15628.4.1.9.1.4",
             "rsuIfaceLogByDir"                : "iso.0.15628.4.1.9.1.5",
             "rsuIfaceName"                    : "iso.0.15628.4.1.9.1.6",
             "rsuSecCredReq"                   : "iso.0.15628.4.1.10",
             "rsuSecCredAttachInterval"        : "iso.0.15628.4.1.11",
             "rsuDsrcChannelModeTable"         : "iso.0.15628.4.1.12",
             "rsuDsrcChannelModeEntry"         : "iso.0.15628.4.1.12.1",
             "rsuDCMIndex"                     : "iso.0.15628.4.1.12.1.1",
             "rsuDCMRadio"                     : "iso.0.15628.4.1.12.1.2",
             "rsuDCMMode"                      : "iso.0.15628.4.1.12.1.3",
             "rsuDCMCCH"                       : "iso.0.15628.4.1.12.1.4",
             "rsuDCMSCH"                       : "iso.0.15628.4.1.12.1.5",
             "rsuWsaServiceTable"              : "iso.0.15628.4.1.13",
             "rsuWsaServiceEntry"              : "iso.0.15628.4.1.13.1",
             "rsuWsaIndex"                     : "iso.0.15628.4.1.13.1.1",
             "rsuWsaPsid"                      : "iso.0.15628.4.1.13.1.2",
             "rsuWsaPriority"                  : "iso.0.15628.4.1.13.1.3",
             "rsuWsaProviderContext"           : "iso.0.15628.4.1.13.1.4",
             "rsuWsaIpAddress"                 : "iso.0.15628.4.1.13.1.5",
             "rsuWsaPort"                      : "iso.0.15628.4.1.13.1.6",
             "rsuWsaChannel"                   : "iso.0.15628.4.1.13.1.7",
             "rsuWsaStatus"                    : "iso.0.15628.4.1.13.1.8",
             "rsuWraConfiguration"             : "iso.0.15628.4.1.14",
             "rsuWraIpPrefix"                  : "iso.0.15628.4.1.14.1",
             "rsuWraIpPrefixLength"            : "iso.0.15628.4.1.14.2",
             "rsuWraGateway"                   : "iso.0.15628.4.1.14.3",
             "rsuWraPrimaryDns"                : "iso.0.15628.4.1.14.4",
             "rsuMessageStats"                 : "iso.0.15628.4.1.15",
             "rsuAltSchMsgSent"                : "iso.0.15628.4.1.15.1",
             "rsuAltSchMsgRcvd"                : "iso.0.15628.4.1.15.2",
             "rsuAltCchMsgSent"                : "iso.0.15628.4.1.15.3",
             "rsuAltCchMsgRcvd"                : "iso.0.15628.4.1.15.4",
             "rsuContSchMsgSent"               : "iso.0.15628.4.1.15.5",
             "rsuContSchMsgRcvd"               : "iso.0.15628.4.1.15.6",
             "rsuContCchMsgSent"               : "iso.0.15628.4.1.15.7",
             "rsuContCchMsgRcvd"               : "iso.0.15628.4.1.15.8",
             "rsuMessageCountsByPsidTable"     : "iso.0.15628.4.1.15.9",
             "rsuMessageCountsByPsidEntry"     : "iso.0.15628.4.1.15.9.1",
             "rsuMessageCountsByPsidIndex"     : "iso.0.15628.4.1.15.9.1.1",
             "rsuMessageCountsByPsidId"        : "iso.0.15628.4.1.15.9.1.2",
             "rsuMessageCountsByPsidCounts"    : "iso.0.15628.4.1.15.9.1.3",
             "rsuMessageCountsByPsidRowStatus" : "iso.0.15628.4.1.15.9.1.4",
             "rsuSystemStats"                  : "iso.0.15628.4.1.16",
             "rsuTimeSincePowerOn"             : "iso.0.15628.4.1.16.1",
             "rsuTotalRunTime"                 : "iso.0.15628.4.1.16.2",
             "rsuLastLoginTime"                : "iso.0.15628.4.1.16.3",
             "rsuLastLoginUser"                : "iso.0.15628.4.1.16.4",
             "rsuLastLoginSource"              : "iso.0.15628.4.1.16.5",
             "rsuLastRestartTime"              : "iso.0.15628.4.1.16.6",
             "rsuIntTemp"                      : "iso.0.15628.4.1.16.7",
             "rsuSysDescription"               : "iso.0.15628.4.1.17",
             "rsuMibVersion"                   : "iso.0.15628.4.1.17.1",
             "rsuFirmwareVersion"              : "iso.0.15628.4.1.17.2",
             "rsuLocationDesc"                 : "iso.0.15628.4.1.17.3",
             "rsuID"                           : "iso.0.15628.4.1.17.4",
             "rsuManufacturer"                 : "iso.0.15628.4.1.17.5",
             "rsuSysSettings"                  : "iso.0.15628.4.1.18",
             "rsuTxPower"                      : "iso.0.15628.4.1.18.1",
             "rsuNotifyIpAddress"              : "iso.0.15628.4.1.18.2",
             "rsuNotifyPort"                   : "iso.0.15628.4.1.18.3",
             "rsuSysLogCloseDay"               : "iso.0.15628.4.1.18.4",
             "rsuSysLogCloseTime"              : "iso.0.15628.4.1.18.5",
             "rsuSysLogDeleteDay"              : "iso.0.15628.4.1.18.6",
             "rsuSysLogDeleteAge"              : "iso.0.15628.4.1.18.7",
             "rsuChanStatus"                   : "iso.0.15628.4.1.19.1",
             "rsuSitData"                      : "iso.0.15628.4.1.20",
             "rsuSdcDestIpAddress"             : "iso.0.15628.4.1.20.1",
             "rsuSdcDestPort"                  : "iso.0.15628.4.1.20.2",
             "rsuSdcInterval"                  : "iso.0.15628.4.1.20.3",
             "rsuSdwIpAddress"                 : "iso.0.15628.4.1.20.4",
             "rsuSdwPort"                      : "iso.0.15628.4.1.20.5",
             "rsuSet"                          : "iso.0.15628.4.1.21",
             "rsuSetRole"                      : "iso.0.15628.4.1.21.1",
             "rsuSetEnable"                    : "iso.0.15628.4.1.21.2",
             "rsuSetSlaveTable"                : "iso.0.15628.4.1.21.3",
             "rsuSetSlaveEntry"                : "iso.0.15628.4.1.21.3.1",
             "rsuSetSlaveIndex"                : "iso.0.15628.4.1.21.3.1.1",
             "rsuSetSlaveIpAddress"            : "iso.0.15628.4.1.21.3.1.2",
             "rsuSetSlaveRowStatus"            : "iso.0.15628.4.1.21.3.1.3",
             "rsuMode"                         : "iso.0.15628.4.1.99",
             }

_rsu_oids = {y:x for x,y in _rsu_mibs.items()}
