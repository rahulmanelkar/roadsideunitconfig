import logging
import invoke
import os
import re

from ... import ssh
from .basics import reboot
from .security import _enroller

from ... import connection
from . import connect


@connection.add_method(connect.CommsigniaConnection)
def configure_rsu(target, immediate=False, keys_path=None, project=None, hsm=True, add_suffix=False, conn_args={}):
    """Configure the RSU to Panasonic specs"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        # Config has setup prompts, setup responders for those
        cloud_proc_watch = invoke.Responder(pattern="Would you like to setup cloud processing?", response="n\n")
        sec_watch = invoke.Responder(pattern="Would you like to set up OBS security processing?", response="y\n")

        # TODO: Verify if suffix is even valid for this scenario

        watch_list = _enroller(ssh_conn, immediate=immediate, keys_path=keys_path, project=project, hsm=hsm, add_suffix=add_suffix)
        watch_list.append(cloud_proc_watch)
        watch_list.append(sec_watch)

        rsu_config = ssh_conn.sudo("/mnt/c3platpersistent/bin/roadside admin configure", 
                                pty=True,
                                watchers=watch_list)

        if rsu_config.return_code != 0:
            logging.error("Failed to configure RSU:\nCode: {rtc}\nStdErr: {err}".format(rtc=rsu_config.return_code, err=rsu_config.stderr))
            raise Exception("Failed to configure the RSU")

    return 0


@connection.add_method(connect.CommsigniaConnection)
def get_radio_fw(target, conn_args={}):
    """Get the current version of the RSU CV2x radio module FW"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        get_fw = ssh_conn.sudo("cat /var/log/cca_version_info.txt", warn=True)

        if get_fw.return_code == 0:
            fw_reg = re.search(r"(v[\d]{1,2}.[\d]{1,2}.[\d]{1,2}.[\d]{1,2})", get_fw.stdout)
            try:
                radio_fw = fw_reg.group(1)
            except IndexError:
                #  Really old radio FW has versions like "LE.UM.0.3.2-38900-9x50 (Post-CS 0.0.100.1)" which isn't caught be the previous regex
                fw_reg =re.search(r"(LE.UM.[\d]{1}.[\d]{1}.[\d]{1}-[\d]{5}-9x50)", get_fw.stdout)
                radio_fw = fw_reg.group(1)
        else:
            logging.error("Failed to get CV2x firmware version:\nCode: {rtc}\nStdErr: {err}".format(rtc=get_fw.return_code, err=get_fw.stderr))
            raise Exception("Failed to get CV2x module firmware version")

    return radio_fw


@connection.add_method(connect.CommsigniaConnection)
def update_device_firmware(target, fw_file, in_place:bool=True, reboot:bool=False, wait_on_reboot:bool=True, conn_args={}):
    """Update the device firwmare using the file pointed to by fw_file. 
    If in_place=True will run update. Otherwise, will run bootstrap"""
    
    with ssh.SshChecker(target, conn_args) as ssh_conn:

        send_file = ssh_conn.put(fw_file)
        # if send_file.return_code != 0:
        #     logging.error("Failed to send file: {fw} to RSU\nCode: {rtc}\nStdErr: {err}".format(fw=fw_file, rtc=send_file.return_code, err=send_file.stderr))
        #     raise Exception("Failed uploading FW file to RSU.")

        # Get JUST the filename.ext from the fw file path
        fw_filename = os.path.basename(fw_file)
        
        fw_extract = ssh_conn.run('tar -xvf {}'.format(fw_filename), hide=True)
        if fw_extract.return_code != 0:
            logging.error("Failed to extract file: {fw}\nCode: {rtc}\nStdErr: {err}".format(fw=fw_filename, rtc=fw_extract.return_code, err=fw_extract.stderr))
            raise Exception("Failed to extract the RSU FW file")

        # The RSU has a method bootstrap and update; update does not overwrite security/certs where bootstrap does. in_place=False will run bootstrap.
        if in_place is False:
            bootstrap_responder = invoke.Responder(pattern="type yes to continue", response="yes\n")

            logging.info("Starting bootstrap...")
            bootstrap = ssh_conn.sudo("signedUpgrade.sh {fw}".format(fw=fw_file), pty=True, watchers=[bootstrap_responder])
            if bootstrap.return_code != 0:
                logging.error("Failed to update FW:\nCode: {rtc}\nStdErr: {err}".format(rtc=bootstrap.return_code, err=bootstrap.stderr))
                raise Exception("Failed to update RSU firmware")
        
        else:
            fw_update = ssh_conn.sudo("signedUpgrade.sh {fw}".format(fw=fw_file))
            if fw_update.return_code != 0:
                logging.error("Failed to update FW:\nCode: {rtc}\nStdErr: {err}".format(rtc=fw_update.return_code, err=fw_update.stderr))
                raise Exception("Failed to update RSU firmware")

        if reboot is True:
            reboot(ssh_conn, wait=wait_on_reboot)
        else:
            logging.warning("FW update requires a reboot. Please reboot unit before use")

    return 0


@connection.add_method(connect.CommsigniaConnection)
def update_radio_firmware(target, fw_file, reboot:bool=False, wait_on_reboot:bool=True, conn_args={}):
    """Update the radio firmware using the specified file in fw_file"""
    
    with ssh.SshChecker(target, conn_args) as ssh_conn:

        send_fw = ssh_conn.put(fw_file)

        fw_name = os.path.basename(fw_file)

        fw_extract = ssh_conn.run('tar -xvf {}'.format(fw_name), hide=True)
        if fw_extract.return_code != 0:
            logging.error("Failed to extract file: {fw}\nCode: {rtc}\nStdErr: {err}".format(fw=fw_name, rtc=fw_extract.return_code, err=fw_extract.stderr))
            raise Exception("Failed to extract the CV2x radio file")

        rsu_stop = ssh_conn.sudo("su -c '/mnt/c3platpersistent/etc/init.d/urb_startup stop'", hide=True, warn=True)
        rsu_halt = ssh_conn.sudo("su -c '/mnt/c3platpersistent/etc/startup.d/998_kapsch_rsu.sh stop'", hide=True, warn=True)

        if rsu_stop.return_code != 0 and rsu_halt.return_code != 0:
            logging.error("Failed to stop CV2x service:\nCode: {rtc}\nStdErr: {err}".format(rtc=rsu_stop.return_code, err=rsu_stop.stderr))
            logging.error("Failed to stop CV2x service:\nCode: {rtc}\nStdErr: {err}".format(rtc=rsu_halt.return_code, err=rsu_halt.stderr))
            raise Exception("Failed to stop CV2x service")

        # The CV2x fw is in CV2x_FW_Name.tar.gz, and must be installed from CV2x_Name folder, get that here
        fw_folder = fw_name.split('.')[0]
        
        radio_inst = ssh_conn.sudo("su -c 'cd {}\n ./update_module.sh ./CS_R120.1'".format(fw_folder), hide=True, warn=True) 

        if radio_inst.return_code != 0:
            logging.error("Failed installing CV2x firmware:\nCode: {rtc}\nStdErr: {err}".format(rtc=radio_inst.return_code, err=radio_inst.stderr))
            raise Exception("Install command of CV2x firmware failed.")

        if reboot is True:
            reboot(ssh_conn, wait=wait_on_reboot)
        else:
            logging.warning("CV2x FW update requires a reboot. Please reboot unit before use")
    
    return 0
