import logging

from ... import ssh
from ... import connection
from . import connect


@connection.add_method(connect.KapschConnection)
def get_firmware(target, conn_args={}):
    """Get the current firmware on the RSU. 
    Useful to pull FW info when SNMP is not connected"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        get_cmd = ssh_conn.run("cat /mnt/c3platpersistent/etc/issue", warn=True, hide=True)

        if get_cmd.return_code == 0:
            out_file = get_cmd.stdout.split('\n')

    return out_file[1]


@connection.add_method(connect.KapschConnection)
def get_dns(target, conn_args={}):
    """Get the current DNS settings"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        get_cmd = ssh_conn.run("cat /etc/resolv.conf", warn=True, hide=True)

        if get_cmd.return_code == 0:
            out_file = get_cmd.stdout.split('\n')

            active_dns = []
            for out_line in out_file:
                if len(active_dns) >= 3 or "# Too many DNS servers configured" in out_line:
                    break
                if out_line.startswith('nameserver'):
                    active_dns.append(out_line.strip('nameserver '))

        else:
            logging.error("Failed to retrieve DNS Settings:\nCode: {rtc}\nStdErr: {err}".format(rtc=get_cmd.return_code, err=get_cmd.stderr))
            raise Exception("Failed to get DNS Settings")

    return active_dns


@connection.add_method(connect.KapschConnection)
def get_ip_addr(target, conn_args={}):
    """Get the set IP address. This may be different than the current IP 
    depending on mode (static vs DHCP) and when the setting was enacted"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        set_ip = ssh_conn.run("cat /etc/eeprom-cb/s.ipv4.addr.0", hide=True)

        if set_ip.return_code != 0:
            logging.error("Failed to get IP address:\nCode: {rtc}\nStdErr: {err}".format(rtc=set_ip.return_code, err=set_ip.stderr))
            raise Exception("Failed to get IP setting")

    return set_ip.stdout


@connection.add_method(connect.KapschConnection)
def get_ip_gateway(target, conn_args={}):
    """Get the currently set gateway"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        set_gw = ssh_conn.run("cat /etc/eeprom-cb/s.ipv4.gw.0", hide=True)

        if set_gw.return_code != 0:
            logging.error("Failed to get IP gateway:\nCode: {rtc}\nStdErr: {err}".format(rtc=set_gw.return_code, err=set_gw.stderr))
            raise Exception("Failed to get IP gateway")

    return set_gw.stdout  


@connection.add_method(connect.KapschConnection)
def get_ip_mode(target, conn_args={}):
    """Get the set IP addressing mode (static vs DHCP).
    This may be different than the current IP mode depending when the setting was enacted"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        ip_mode = ssh_conn.run("cat /etc/eeprom-cb/s.ipv4.mode.0", hide=True)

        if ip_mode.return_code != 0:
            logging.error("Failed to get IP address mode:\nCode: {rtc}\nStdErr: {err}".format(rtc=ip_mode.return_code, err=ip_mode.stderr))
            raise Exception("Failed to get IP mode")

    return ip_mode.stdout


@connection.add_method(connect.KapschConnection)
def set_dhcp(target, conn_args={}):
    """Set the RSU to DHCP mode. Needs Reboot to apply new setting"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        write_cmd = ssh_conn.sudo("""su -c "echo -n "dhcp" > /etc/eeprom-cb/s.ipv4.mode.0" """, warn=True)

        if write_cmd.return_code != 0:
            logging.error("Failed writing DHCP mode:\nCode: {rtc}\nStdErr: {err}".format(rtc=write_cmd.return_code, err=write_cmd.stderr))
            raise Exception("Failed writing DHCP mode.")

        eeprom_enable = ssh_conn.sudo('su -c "/bin/eeprom_write_enable.sh 1"')
        if eeprom_enable.return_code != 0:
            logging.critical("Failed to enable eeprom writes:\nCode: {rtc}\nStdErr: {err}".format(rtc=eeprom_enable.return_code, err=eeprom_enable.stderr))
            raise Exception("Failed to enable eeprom writes. Cannot continue")

        eeprom_write = ssh_conn.sudo('su -c "/bin/eeprom_tool.py I /etc/eeprom-cb/"')
        if eeprom_write.return_code != 0:
            logging.critical("Failed to write values to eeprom:\nCode: {rtc}\nStdErr: {err}".format(rtc=eeprom_enable.return_code, err=eeprom_enable.stderr))
            raise Exception("Failed to write new values. Cannot continue")

        eeprom_disable = ssh_conn.sudo('su -c "/bin/eeprom_write_enable.sh 0"')
        if eeprom_disable.return_code != 0:
            logging.warning("Failed to disable eeprom writes:\nCode: {rtc}\nStdErr: {err}".format(rtc=eeprom_enable.return_code, err=eeprom_enable.stderr))

    return 0


@connection.add_method(connect.KapschConnection)
def set_dns(target, dns_ips, conn_args={}):
    """Take one or more DNS addresses and set them on the RSU"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        if isinstance(dns_ips, list):
            dns_str = ""
            for dns in dns_ips:
                dns_str += "{} ".format(dns)
        else:
            if ',' in dns_ips:
                dns_str = ""
                for dns in dns_ips.split(','):
                    dns_str += "{} ".format(dns)
            else:
                dns_str = str(dns_ips)

        dns_set = ssh_conn.sudo('update_ipconfig.sh ipv4_dns {dns}'.format(dns=dns_str))

        if dns_set.return_code != 0:
            logging.error("Failed to set DNS properly:\nCode: {rtc}\nStdErr: {err}".format(rtc=dns_set.return_code, err=dns_set.stderr))
            raise Exception("Failed to configure DNS")

    return 0


@connection.add_method(connect.KapschConnection)
def set_static_ip(target, new_ip, new_gw, conn_args={}):
    """Set a new static IP address and gateway on the current RSU. Needs Reboot to apply new address"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
    
        write_str = """su -c "echo -n 'static' > /etc/eeprom-cb/s.ipv4.mode.0\n
                    echo -n '{gateway}' > /etc/eeprom-cb/s.ipv4.gw.0\n
                    echo -n '{ip}/24' > /etc/eeprom-cb/s.ipv4.addr.0\n" """.format(ip=new_ip, gateway=new_gw)

        write_cmd = ssh_conn.sudo(write_str, warn=True, hide=True)

        if write_cmd.return_code != 0:
            logging.error("Failed configuring new IP or gateway:\nCode: {rtc}\nStdErr: {err}".format(rtc=write_cmd.return_code, err=write_cmd.stderr))
            raise Exception("Failed configuring new IP or gateway.")

        eeprom_enable = ssh_conn.sudo('su -c "/bin/eeprom_write_enable.sh 1"', hide=True)
        if eeprom_enable.return_code != 0:
            logging.critical("Failed to enable eeprom writes:\nCode: {rtc}\nStdErr: {err}".format(rtc=eeprom_enable.return_code, err=eeprom_enable.stderr))
            raise Exception("Failed to enable eeprom writes. Cannot continue")

        eeprom_write = ssh_conn.sudo('su -c "/bin/eeprom_tool.py I /etc/eeprom-cb/"')
        if eeprom_write.return_code != 0:
            logging.critical("Failed to write values to eeprom:\nCode: {rtc}\nStdErr: {err}".format(rtc=eeprom_enable.return_code, err=eeprom_enable.stderr))
            raise Exception("Failed to write new values. Cannot continue")

        eeprom_disable = ssh_conn.sudo('su -c "/bin/eeprom_write_enable.sh 0"', hide=True)
        if eeprom_disable.return_code != 0:
            logging.warning("Failed to disable eeprom writes:\nCode: {rtc}\nStdErr: {err}".format(rtc=eeprom_enable.return_code, err=eeprom_enable.stderr))

        new_ip = ssh_conn.run("cat /etc/eeprom-cb/s.ipv4.addr.0", hide=True)
        new_gw = ssh_conn.run("cat /etc/eeprom-cb/s.ipv4.gw.0", hide=True)

    return {"ip" : new_ip.stdout, "gateway": new_gw.stdout}


@connection.add_method(connect.KapschConnection)
def reboot(target, wait:bool=True, conn_args={}):
    """Reboot the unit. By default the command will not complete until the reboot command closes the connection. 
    Set wait=False to instead issue reboot as a background command that completes immediately. 
    It make take a few seconds before the reboot command is processed if it is issued async"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        if wait is False:
            # Default action is to reboot the unit and wait for the connection to close. 
            # This issues reboot to complete 1 minute in the future but returns immediately
            reboot_cmd = ssh_conn.sudo("shutdown --reboot +1", warn=True)
            
            if reboot_cmd.return_code == 0:
                ssh_conn.close()
                return 0
            else:
                logging.error("REBOOT failed:\nCode: {rtc}\nStdErr: {err}".format(rtc=reboot_cmd.return_code, err=reboot_cmd.stderr))
                raise Exception("Reboot Failed")

        else:
            reboot_cmd = ssh_conn.sudo("reboot", warn=True)

            if reboot_cmd.return_code == 0:
                ssh_conn.close()
                return 0
            else:
                logging.error("REBOOT failed:\nCode: {rtc}\nStdErr: {err}".format(rtc=reboot_cmd.return_code, err=reboot_cmd.stderr))
                raise Exception("Reboot Failed")
