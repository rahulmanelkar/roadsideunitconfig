import logging
import invoke

from ... import ssh
from ... import connection
from . import connect



@connection.add_method(connect.CommsigniaConnection)
def get_active_radios(target, conn_args={}):
    """Get the currently active radio(s). Possible returns are None, 'cv2x', 'dsrc', 'dualmode' """

    with ssh.SshChecker(target, conn_args) as ssh_conn:
    
        radio_return = ssh_conn.run("cat /etc/eeprom-cb/a.dualradio.mode", hide=True, warn=True)

        if radio_return.return_code == 0:
            if "CCA" in radio_return.stdout and "NXP" in radio_return.stdout:
                radio_mode = "dualmode"
            elif "CCA"in radio_return.stdout:
                radio_mode = "cv2x"
            elif "NXP" in radio_return.stdout:
                radio_mode = "dsrc"
            else:
                radio_mode = None
        else:
            logging.error("Get Radios: Remote ssh Command Error::\nCode: {rtc}\nStdErr: {err}".format(rtc=radio_return.return_code, err=radio_return.stderr))
            raise Exception("Failed to determine active radios")

    return radio_mode


@connection.add_method(connect.CommsigniaConnection)
def get_cv2x_channel(target, conn_args={}):
    """Return the currently set cv2x channel as an int"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
    
        cv2x = ssh_conn.run("cat /var/log/cca_capabilities.txt | grep -i channel", hide=True, warn=True)

        if cv2x.return_code == 0:
            cv2x_ch = cv2x.stdout.split()[1]
        else:
            logging.error("Get CV2x channel: Remote ssh Command Error::\nCode: {rtc}\nStdErr: {err}".format(rtc=cv2x.return_code, err=cv2x.stderr))
            raise Exception("Failed to get CV2X channel")
        
    return int(cv2x_ch)


@connection.add_method(connect.CommsigniaConnection)
def set_active_radios(target,cv2x:int, dsrc:int, reboot:bool=False, wait_on_reboot:bool=True,  conn_args={}):
    """Choose whether to enable or disable the cv2x and dsrc radios. Set to 0 for off, 1 for on. 
    Unit requires reboot after radio changes, set reboot=True to perform this action automatically. Default is to not reboot.
    Wait on reboot determines whether to wait for the connection to close, or to issue the reboot command asynchronously: see basics.reboot()"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
        
        radio_resp = []
        for radio_on in cv2x, dsrc:
            if int(radio_on == 1):
                radio_resp.append( "y\n")
            elif int(radio_on == 0):
                radio_resp.append("n\n")
            else:
                raise ValueError("Radio setting must be either 0 or 1: {} is invalid".format(radio_on))
        
        # Config watchers/responders for radio prompts
        cv2x_watch = invoke.Responder(pattern="Enable radio CCA?", response=radio_resp[0])
        dsrc_watch = invoke.Responder(pattern="Enable radio NXP?", response=radio_resp[1])

        radio_on = ssh_conn.sudo("/mnt/c3platpersistent/bin/roadside admin al-config", pty=True, watchers=[dsrc_watch, cv2x_watch])

        if radio_on.return_code == 0:
        
            if reboot is True:
                # The unit requires a restart. If reboot=True, then issue the restart command as part of the process. Otherwise, leave it up to the user.
                reboot_cmd = ssh.kapsch.reboot(ssh_conn, wait=wait_on_reboot)
                if reboot_cmd != 0:
                    raise Exception("Reboot command failed")
            else:
                logging.warning("USER Skipped REBOOT. Please reboot the unit before use.")
            
            return 0

        else:
            logging.error("Failed to set radio modes:\nCode: {rtc}\nStdErr: {err}".format(rtc=radio_on.return_code, err=radio_on.stderr))
            return 1
            

@connection.add_method(connect.CommsigniaConnection)
def set_cv2x_channel(target, cv2x_ch:int, reboot:bool=False, wait_on_reboot:bool=True, conn_args={}):
    """Set the CV2X channel to the given value.
    Unit requires reboot after radio changes, set reboot=True to perform this action automatically. Default is to not reboot. 
    Wait on reboot determines whether to wait for the connection to close, or to issue the reboot command asynchronously: see basics.reboot()"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        ch_watcher = invoke.Responder(pattern="type yes to continue", response="yes\n")
        # newer firmwares changed the prompts, watch for both
        new_fw_ch_watcher = invoke.Responder(pattern="Would you like to overwrite current configuration?", response="yes\n")

        ch_set = ssh_conn.sudo('su -c "export PATH=/mnt/c3platpersistent/bin:$PATH && /mnt/c3platpersistent/bin/update_channel.sh -c {}"'.format(cv2x_ch),
                            pty=True, watchers=[ch_watcher, new_fw_ch_watcher], warn=True)

        if ch_set.return_code == 0:
            if reboot is True:
                # The unit requires a restart. If reboot=True, then issue the restart command as part of the process. Otherwise, leave it up to the user.
                reboot_cmd = ssh.kapsch.reboot(ssh_conn, wait=wait_on_reboot)
                if reboot_cmd != 0:
                    raise Exception("Reboot command failed")
            else:
                logging.warning("USER Skipped REBOOT. Please reboot the unit before use.")
            
            return 0
        
        else:
            logging.error("Failed to set CV2x channel:\nCode: {rtc}\nStdErr: {err}".format(rtc=ch_set.return_code, err=ch_set.stderr))
            return 1
