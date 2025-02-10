
import logging
import fabric
import invoke
import paramiko

import rsu_toolkit



class CommsigniaConnection(fabric.Connection):
    """Create a Commsignia sub-class of connection. This gets created on object creation to allow
    rsu_toolkit.connection.add_method to work conditionally on vendors"""

    def __init__(self, target_ip, user='admin', pw='admin', sudo_pw="admin", priv_key=None, gateway=None):

        # Pass data to the standard fabric.Connection init and set fabric.Connection.Config once instead of every time
        config = fabric.Config(overrides={'sudo': {'password': sudo_pw}})

        if priv_key is not None:
            super().__init__(target_ip, user=user, connect_kwargs={"key_filename": priv_key}, config=config, gateway=gateway, connect_timeout=15)
        else:
            super().__init__(target_ip, user=user, connect_kwargs={"password": pw, "allow_agent": False}, config=config, gateway=gateway, connect_timeout=15)

        # These values must be passed in to connect
        self.ip = target_ip
        self.username = user
        self.password = pw
        self.priv_key = priv_key

        # Used if a command is run using self.sudo('')
        self.sudo_pass = sudo_pw

        # Attributes that must be run on a connected host go here

        # TODO: Need to revise this. Right now it can sometimes raise an Exception on failure, or sometimes just set self.connected = 0
        #  It's useful to allow a failed ssh to continue if snmp succeeded so that snmp commands can still run
        #  however, it will be very messy to try to handle multiple possible failure paths.
        #  It's probably best to just to capture for logging sake, then re-raise the Exceptions
        try:
            self.rsu_name = self.run('hostname', hide=True, timeout=15).stdout.strip()
            logging.critical("SSH_CONNECTION established: {} : {}".format(self.rsu_name, self.ip))
            self.connected = 1
        except invoke.exceptions.UnexpectedExit:
            # This means the SSH connection worked, but the RSU has disabled the 'hostname' command
            self.rsu_name = "Unknown"
            logging.warning("SSH_CONNECTION could not get hostname: {}".format(self.ip))
            self.connected = 1
        except TimeoutError:
            # This means the SSH connection attempt timed out
            self.rsu_name = None
            logging.error("SSH_CONNECTION timed out: {}".format(self.ip))
            self.connected = 0
            raise      
        except invoke.exceptions.CommandTimedOut:
            # This means the command timed out on the RSU, not the SSH conn. Would be a very weird occurrance
            self.rsu_name = None
            logging.error("SSH_CONNECTION command timed out: {}".format(self.ip))
            self.connected = 0
            raise
        except paramiko.ssh_exception.ChannelException:
            # This means the SSH connection was rejected
            self.rsu_name = None
            logging.error("SSH_CONNECTION rejected: {}".format(self.ip))
            self.connected = 0
            raise
