import logging
import invoke
import re
from datetime import datetime, timedelta
import os 
from packaging import version

from ... import ssh
from ... import connection
from . import connect
from .basics import get_firmware


@connection.add_method(connect.CommsigniaConnection)
def apply_cert(target, filename, conn_args={}):
    """Apply the generated enrollment request"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        ssh_conn.put(filename)

        response_name = os.path.basename(filename)
        apply_cmd = ssh_conn.sudo("security_process_enrollment.sh {}".format(response_name), hide=False, warn=True)

        if apply_cmd.return_code != 0:
            logging.error("Failed to apply Cert Response {crt}\nCode: {rtc}\nStdErr: {err}\n{out}".format(
                                crt=response_name, rtc=apply_cmd.return_code, err=apply_cmd.stderr, out=apply_cmd.stdout))
            raise Exception("Failed to apply Cert Response")

    return 0


@connection.add_method(connect.CommsigniaConnection)
def generate_iss_request(target, immediate=False, keys_path=None, project=None, hsm=True, add_suffix=False, conn_args={}):
    """Send a request to the system to generate a Cert Request. 
    If immediate=True, the RSU will try immediate enrollment. This requires the user to provide a path to the local keys location
    If running immediate=True, the customer should be given using project=
    If immediate=False, or immediate=True fails, the RSU will generate a file that can be sent to ISS for processing"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
        watch_list = _enroller(ssh_conn, immediate=immediate, keys_path=keys_path, project=project, hsm=hsm, add_suffix=add_suffix)

        gen_cmd = ssh_conn.sudo("security_reenroll.sh", warn=True, pty=True, watchers=watch_list)

    if gen_cmd.return_code != 0:
        logging.error("Generate enrollment failed:\nCode: {rtc}\nStdErr: {err}".format(rtc=gen_cmd.return_code, err=gen_cmd.stderr))
        raise Exception("Generate enrollment failed with: {err}".format(err=gen_cmd.stderr))

    regex_file = re.search("Enrollment request ready at (.*)!  Please send it to the service desk for processing.", gen_cmd.stdout)
    # regex_file should exist if immediate=False or if immediate=True auto enroll failed
    if regex_file:
        file_loc = regex_file.group(1)
        logging.info("Security: ISS file is saved at {loc}".format(loc=file_loc))
        return file_loc
    else:
        return gen_cmd.return_code


@connection.add_method(connect.CommsigniaConnection)
def get_cert_status(target, conn_args={}):
    """Get the status of the RSU security Certificates. Can be none, partial, expired, or pass"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        sec_cmd = ssh_conn.sudo("ls -la /mnt/c3platpersistent/etc/aerolink/ieee/state/certificates --time-style=long-iso", warn=True)
    
    cert_status = "none"
    
    if sec_cmd.return_code != 0:
        logging.error("Get Certificates command failed:\nCode: {rtc}\nStdErr: {err}".format(rtc=sec_cmd.return_code, err=sec_cmd.stderr))
        raise Exception("Get certificates command failed with {err}".format(err=sec_cmd.stderr))

    certificates = sec_cmd.stdout.split("\n")[1:-1]   # splits output into list and discards useless first and blank last entry

    if 6 < len(certificates) < 18:
        logging.warning("Security: Partial Certificates")
        cert_status = "partial"
        
    elif len(certificates) >= 18:

        acf_files = 0
        acf_pass = 0
        for cert in certificates:
            if cert.endswith(".acf"):
                # Count acf files. Should have 2
                acf_files += 1
                
                last_modified_str = cert.split()[5] + " " + cert.split()[6]

                last_modified = datetime.strptime(last_modified_str, '%Y-%m-%d %H:%M')

                delta_actual = datetime.utcnow() - last_modified

                if delta_actual < timedelta(days=14):
                    # count number of acf files that are up-to-date
                    acf_pass += 1

        if acf_files == 0 and acf_pass == 0:
            cert_status = "missing"
            logging.warning("Security: Certs are MISSING")
        elif acf_pass == 0 and acf_files > 0:
            cert_status = "expired"
            logging.warning("Security: Certs are EXPIRED")
        elif acf_pass < acf_files:
            cert_status = "partial-expired"
            logging.warning("Security: RSU is currently secured, but at least one Cert is EXPIRED")
        elif acf_pass == acf_files:
            logging.info("Security: Certs are up-to-date")
            cert_status = "pass"
        else:
            logging.error("No idea how this happened")
            cert_status = "unknown"

    else:
        cert_status = "missing"
        logging.warning("Security: Certs are MISSING")
        # TODO: Figure out if there are edge pass cases with files <18
        
    return cert_status


@connection.add_method(connect.CommsigniaConnection)
def pull_cert_request(target, filename=None, local='.', conn_args={}):
    """Retrieve a perviously generated Cert request file and save to the local system.
    The file will be saved to: local=/path/to/local/$rsuSerialNumber/$CertFilename.zip.
    Will look for remote file with name defined in filename=. If filename=None, 
    will look for a remote file with name='{rsuSerialNumber}.zip.' """
    
    with ssh.SshChecker(target, conn_args) as ssh_conn:

        # Determine remote filename and create needed directory structure
        cert_remote_loc = filename if filename is not None else ssh_conn.rsu_name
        rsu_dir = os.path.join(os.path.abspath(local), ssh_conn.rsu_name)
        cert_name = cert_remote_loc.split('/')[-1]
        
        if not os.path.isdir(rsu_dir):
            os.makedirs(rsu_dir)

        if cert_remote_loc.endswith('.zip'):
            local_file = os.path.join(rsu_dir, cert_name)
            get_file = ssh_conn.get(cert_remote_loc, local=local_file)
            
        else:
            local_file = os.path.join(rsu_dir, "{}.zip".format(cert_name))
            get_file = ssh_conn.get("{}.zip".format(cert_remote_loc), local=local_file)

    return local_file


@connection.add_method(connect.CommsigniaConnection)
def check_iss(target, timeout=10, conn_args={}):
    """Check if the ISS server is reachable from the device"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        iss_check = ssh_conn.run(f'timeout {timeout} wget https://ra.pilot.v2x.isscms.com:8892', warn=True)

        if str(iss_check.return_code) == '8':
            logging.info('Security: ISS server is reachable')
            return True
        elif str(iss_check.return_code) == '124':
            logging.warning('Security: ISS server timed out')
            return False
        else:
            logging.error(f'Security: ISS server status unknown: {iss_check.return_code}')
            return False


@connection.add_method(connect.CommsigniaConnection)
def _set_network_ping(target, local_file=None, remote_target="127.0.0.1", conn_args={}):
    """Kapsch only. Reconfigure the network checker to use a new target. Solves firewall blocking issues"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        script_check = ssh_conn.run('test -f "/mnt/c3platpersistent/bin/network_availability_host.sh"', warn=True)

        # If it's not there, put it there
        if script_check.return_code != 0:
            if local_file is None or "network_availability_host.sh" not in local_file:
                logging.error("Security: No local path or remote path of network_availability_host.sh.")
                raise Exception("network_availability_host.sh is not available")
            else:
                ssh_conn.put(local_file)
                
                mv_cmd = ssh_conn.sudo("mv network_availability_host.sh /mnt/c3platpersistent/bin/", warn=True)
                if mv_cmd.return_code != 0:
                    logging.error("Security: Failed moving network_availability_host.sh:\nCode: {rtc}\nStdErr: {err}".format(rtc=mv_cmd.return_code, err=mv_cmd.stderr))
                    raise Exception("Failed to move network_availability_host.sh to /mnt/c3platpersistent/bin/network_availability_host.sh")
        
        chmod_cmd = ssh_conn.sudo("chmod 777 /mnt/c3platpersistent/bin/network_availability_host.sh", warn=True)
        if chmod_cmd.return_code != 0:
            logging.error("Security: Failed setting permission on network_availability_host.sh:\nCode: {rtc}\nStdErr: {err}".format(rtc=chmod_cmd.return_code, err=chmod_cmd.stderr))
            raise Exception("Failed to move network_availability_host.sh to /mnt/c3platpersistent/bin/network_availability_host.sh")

        # Check the current setting, and leave it alone if it's already set correctly
        curr_net = ssh_conn.sudo("/mnt/c3platpersistent/bin/network_availability_host.sh get", warn=True)
        if curr_net.return_code == 0:
            regex_net = re.search("The host address is (.*) on this device! trying to ping (.*)", curr_net.stdout)
            if regex_net:
                # leave it alone if it's already set correctly
                if regex_net.group(2) == remote_target:
                    logging.info("Security: Device already set to {}".format(remote_target))
                    return regex_net.group(2)
            else:
                logging.warning("Getting the current network_availability_host.sh setting failed. Attempting a set anyway...")
        else:
            logging.warning("Security: Failed running 'network_availability_host.sh get':\nCode: {rtc}\nStdErr: {err}".format(rtc=curr_net.return_code, err=curr_net.stderr))
        
        # Try to set it if it's not set correctly or if it is a different value
        set_cmd = ssh_conn.sudo("/mnt/c3platpersistent/bin/network_availability_host.sh set {}".format(remote_target))
        if set_cmd.return_code == 0:
            return remote_target
        else:
            logging.error("Failed to change Security ping location:\nCode: {rtc}\nStdErr: {err}".format(rtc=set_cmd.return_code, err=set_cmd.stderr))
            raise Exception("Failed to change Security ping location")


def _enroller(ssh_conn, immediate=False, keys_path=None, project=None, hsm=True, add_suffix=False):
    """Enrollment processor that can be resused by generate_iss_request() AND firmware.configure_rsu()"""

    project_id = {"psn":   1,
                  "udot":  2,
                  "gdot":  3,
                  "cdot":  4,
                  "txdot": 5,
                  }
    
    # Kapsch changed profile num of "Panasonic". Need way to ID it for profile_watch. 2 options:
    # TODO: Stream the stdout to a buffer, yield each line, and find the matching line to determine number
    #           Fabric doesn't appear to support this, would have to create own method and I'm not sure it's even been done before
    # OR: Use the FW version to know what the profile index is; must capture via ssh as this cmd does NOT need a valid SNMP conn to run
    # Update 01/19/2023: Added 9 to handle 1.35 security enrollment changes
    try:
        fw_ver = get_firmware(ssh_conn)

        if version.parse(fw_ver.split('-')[0]) < version.parse('1.32'):
            prof_resp = "5\n"
        elif  version.parse(fw_ver.split('-')[0]) == version.parse('1.35'):
            prof_resp = "9\n"
        elif version.parse(fw_ver.split('-')[0]) >= version.parse('1.32'):
            prof_resp = "8\n"
        else:
            raise Exception(f"Version failure: unrecognized version: {fw_ver}")
    except:
        logging.error("ENROLLER: Unable to determine FW version")
        raise
    
    verify_watch = invoke.Responder(pattern="Ctrl-C to abort or enter to continue", response="\n")
    profile_watch = invoke.Responder(pattern="Enter a profile number to use or 0 for defaults", response=prof_resp)
    rsu_watch = invoke.Responder(pattern="Is this an RSU or an OBU", response='R\n')

    if add_suffix is True or immediate is True:
        # In order to auto_enroll, the file must have a suffix that's never been used before. To do that, I've decide to append the time
        t_now = datetime.now()
        str_t_now = t_now.strftime("_%Y%m%d_%H%M%S\n")
        suffix_watch = invoke.Responder(pattern="Enter a suffix to be added to the serial number or leave blank to send as is",
                                        response=str_t_now)
    else:
        suffix_watch = invoke.Responder(pattern="Enter a suffix to be added to the serial number or leave blank to send as is", response="\n")

    if hsm is True:
        hw_sec_watch = invoke.Responder(pattern="Would you like to use hardware security for private key storage?", response="y\n")
    else:
        hw_sec_watch = invoke.Responder(pattern="Would you like to use hardware security for private key storage?", response="n\n")

    if immediate is False:
        immediate_watch = invoke.Responder(pattern="Would you like to proceed with immediate enrollment", response="n\n")
        watch_list = [verify_watch, hw_sec_watch, suffix_watch, profile_watch, immediate_watch, rsu_watch]
    else:
        if keys_path is None or project is None:
            logging.error("Must provide keys_path= and project= if immediate=True")
            raise TypeError("Must provide keys_path= and project= if immediate=True")
        
        try:
            proj_key = project_id[project.lower()]
        except KeyError:
            logging.error("Security: Unrecognized customer: project {inp} is not recognized. Known customers are\n {c}".format(inp=project.lower(), c=list(project_id.keys())))
            raise
        
        # Move keys from local to RSU
        ssh_conn.put(os.path.join(keys_path, "key.pem"))
        ssh_conn.put(os.path.join(keys_path, "cert.pem"))

        immediate_watch = invoke.Responder(pattern="Would you like to proceed with immediate enrollment", response="y\n")
        deployment_watch = invoke.Responder(pattern="Enter a PO to use from the list above", response="{}\n".format(proj_key))
        pilot_watch = invoke.Responder(pattern="Is this enrollment against the pilot system?", response="y\n")
        key_watch = invoke.Responder(pattern="Enter the location of the directory with the correct cert.pem and key.pem files for the pilot site:",
                                        response="/home/admin\n")

        watch_list = [verify_watch, hw_sec_watch, suffix_watch, profile_watch, immediate_watch,
                      deployment_watch, pilot_watch, key_watch, rsu_watch]
 
    return watch_list
