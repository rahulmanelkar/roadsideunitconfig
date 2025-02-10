import logging

from . import connect as snmpconn
from .exceptions import snmpGeneralError

from .. import connection

# TODO: This needs to be tested


@connection.add_method(snmpconn.SnmpConnection)
def create_user(target, new_un="newuser", new_authkey="newpassword", new_passphrase=None, snmp_args={}, hide=True, **kwargs):
    """Create a new snmp user. This will clone the user that is given as login user in snmp_args"""

    with snmpconn.SnmpChecker(target, snmp_args) as snmp:
    
        try:
            snmp_view = snmp._vacm("createView all .1 80", warn=True, hide=hide)
            snmp_acc = snmp._vacm("createAccess RWGroup 3 3 1 all all none", warn=True, hide=hide)

        except snmpGeneralError as e:
            logging.warning("SNMP USER: Failed creating access groups. This may happen if this command has been run on the unit in the past:\n{}".format(e))

        clone = snmp._usm("create", snmp.user, new_val=new_un, warn=True, hide=hide)

        new_u_str = "createSec2Group 3 {newuser} RWGroup".format(newuser=new_un)
        try:
            new_u_cfg = snmp._vacm(new_u_str)
        except snmpGeneralError as e:
            logging.warning("SNMP USER: Failed to give access to '{new}'. This may happen if this command has been run on the unit in the past:\n{e}".format(new=new_un, e=e))

        if new_authkey is None and new_passphrase is None:
            logging.warning("SNMP USER: '{new}' has same passphrase and authKey as '{old}'.".format(new=new_un, old=snmp.user))
            new_profile = {"username": new_un, "authkey": snmp.authkey, "passphrase": snmp.passphrase}
        else:
            # Create a new snmp connection, as we need to use the new user name for pw changes
            snmp_new = snmpconn.SnmpConnection(target, username=new_un, authkey=snmp.authkey, authprotocol=snmp.authprotocol, passphrase=snmp.passphrase, encryption=snmp.encryption, gateway=snmp.gateway)
            new_profile = change_password(snmp_new, new_authkey=new_authkey, new_passphrase=new_passphrase, hide=hide)

    return new_profile


@connection.add_method(snmpconn.SnmpConnection)
def change_password(target, new_authkey=None, new_passphrase=None, snmp_args={}, hide=True, **kwargs):
    """Change the password of the current user"""
    
    with snmpconn.SnmpChecker(target, snmp_args) as snmp:
    
        if new_authkey is None and new_passphrase is None:
            raise TypeError("Must be provide either new_authkey, new_passphrase, or both as input")
        elif new_authkey is not None and new_passphrase is None:
            pw_type = ["-Ca passwd"]

        elif new_authkey is None and new_passphrase is not None:
            pw_type = ["-Cx passwd"]

        elif new_authkey == new_passphrase:
            pw_type = ["-Ca passwd", "-Cx passwd"]

        else:
            pw_type = ["-Ca passwd", "-Cx passwd"]

            for pw_op in pw_type:
                if pw_op == "-Ca passwd":
                    snmp._usm(pw_op, snmp.authkey, new_val=new_authkey, warn=True, hide=hide)
                    # This updates the object's saved password to match the change
                    snmp.authkey = new_authkey
                elif pw_op == "-Cx passwd":
                    snmp._usm(pw_op, snmp.passphrase, new_val=new_passphrase, warn=True, hide=hide)
                    # This updates the object's saved password to match the change
                    snmp.passphrase = new_passphrase

    return {"username": snmp.user, "authkey": snmp.authkey, "passphrase": snmp.passphrase}


@connection.add_method(snmpconn.SnmpConnection)
def delete_user(target, username_to_delete,  snmp_args={}, hide=True, **kwargs):
    """Delete the snmp profile of the given user"""
    
    with snmpconn.SnmpChecker(target, snmp_args) as snmp:
    
        del_cmd = snmp._usm("delete", username_to_delete, hide=hide, **kwargs)

        if del_cmd.return_code != 0:
            logging.error("SNMP USER: Delete user '{un}' failed:\nCode: {rtc}\n StdErr: {err}".format(un=username_to_delete, rtc=del_cmd.return_code, err=del_cmd.stderr))
            raise Exception("Failed to delete snmp user")

    return 0
        