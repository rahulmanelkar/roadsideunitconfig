import logging

from ... import ssh
from ... import connection
from . import connect
import time


@connection.add_method(connect.CommsigniaConnection)
def add_public_key(target, key, conn_args={}):
    """Add a new public key to the RSU"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        key_cmd = ssh_conn.sudo("/mnt/c3platpersistent/bin/manage-users --pubkey '{key}' update {un}".format(key=key, un=ssh_conn.username), warn=True)

        if key_cmd.return_code != 0:
            logging.error("User: Failed to set the public key:\nCode: {rtc}\nStdErr: {err}".format(rtc=key_cmd.return_code, err=key_cmd.stderr))
            raise Exception("Failed to set the user's public key")

        return ssh_conn.username, key


@connection.add_method(connect.CommsigniaConnection)
def change_password(target, new_user, new_pw, conn_args={}):
    """Change the password"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
    
        #pw_cmd = ssh_conn.sudo("/mnt/c3platpersistent/bin/manage-users --password '{pw}' update {un}".format(pw=new_pw, un=ssh_conn.username), warn=True)
        pw_cmd = ssh_conn.run("passwd {un}".format(un=new_user), warn=True)
        #time.sleep(1)
        #pw_cmd = ssh_conn.run("{pw}".format(pw=new_pw), warn=True)
        #pw_cmd = ssh_conn.sudo("{pw}".format(pw=new_pw), warn=True)

        if pw_cmd.return_code != 0:
            logging.error("Failed to update user {un}'s password:\nCode: {rtc}\nStdErr: {err}".format(un=ssh_conn.username, rtc=pw_cmd.return_code, err=pw_cmd.stderr))
            raise Exception("Failed to set the user's password")

        return ssh_conn.username, new_pw


@connection.add_method(connect.CommsigniaConnection)
def create_user(target, new_user, new_pw, public_key=None, conn_args={}):
    """Create a new user. If public_key is not None, set up a key pair"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
        
        if public_key is None:
            #create_cmd = ssh_conn.sudo("/mnt/c3platpersistent/bin/manage-users --password '{pw}' --groups sudo,kapsch add {un}".format(pw=new_pw, un=new_user), warn=True)
            create_cmd = ssh_conn.run("useradd {un}".format(un=new_user), warn=True)
        else:
            create_cmd = ssh_conn.sudo("/mnt/c3platpersistent/bin/manage-users --password '{pw}' --pubkey '{key}' --groups sudo,kapsch add {un}".format(pw=new_pw, un=new_user, key=public_key), warn=True)

        if create_cmd.return_code != 0:
            logging.error("Failed to create user {un}:\nCode: {rtc}\nStdErr: {err}".format(un=new_user, rtc=create_cmd.return_code, err=create_cmd.stderr))
            raise Exception("Failed to create a new user")

    return new_user, new_pw, public_key


@connection.add_method(connect.CommsigniaConnection)
def disable_user(target, del_user, conn_args={}):
    """Disable the given user"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
        
        #del_cmd = ssh_conn.sudo("/mnt/c3platpersistent/bin/manage-users disable {}".format(del_user), warn=True)
        del_cmd = ssh_conn.run("userdel {}".format(del_user), warn=True)

        if del_cmd.return_code != 0:
            logging.error("Failed to disable user {un}:\nCode: {rtc}\nStdErr: {err}".format(un=del_user, rtc=del_cmd.return_code, err=del_cmd.stderr))
            raise Exception("Failed to disable user")

    return del_user
