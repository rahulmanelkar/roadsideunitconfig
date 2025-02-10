import logging
import paramiko
from scp import SCPClient
import json


def read_ifm_port():
    with open('srm-ifm-tool.json', 'r+') as ifm_config_file:
        ifm_config_data = json.load(ifm_config_file)
    return ifm_config_data['listenPort']


def read_ifm_config():
    with open('srm-ifm-tool.json', 'r+') as ifm_config_file:
        ifm_config_data = json.load(ifm_config_file)
    return ifm_config_data


def edit_ifm_port(port):
    if not type(port) == int:
        raise ValueError('Error: port number not valid')
    with open('srm-ifm-tool.json', 'r+') as ifm_config_file:
        ifm_config_data = json.load(ifm_config_file)
        ifm_config_data['listenPort'] = str(port)
        ifm_config_file.seek(0)
        json.dump(ifm_config_data, ifm_config_file)
        ifm_config_file.truncate()


def get_ifms(target, username, password):
    """Get all entries in the Immediate Forward Table"""

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname = target, username = username, password = password, port = 22)
    scp_client = SCPClient(ssh_client.get_transport())
    scp_client.get('/rwdata/v2x_configs/srm-ifm-tool.json')
    scp_client.close()
    ssh_client.close()
    


def set_ifms(target, username, port, password):
    """Set all ports in the Immediate Forward Table"""
    edit_ifm_port(port)
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname = target, username = username, password = password, port = 22)
    scp_client = SCPClient(ssh_client.get_transport())
    scp_client.put('srm-ifm-tool.json','/rwdata/v2x_configs/srm-ifm-tool.json')
    scp_client.close()
    ssh_client.close()


def firewall_config(target, username, password, port):
    """Open firewall udp port"""
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname = target, username = username, password = password, port = 22)
    ssh_client.exec_command('uci add firewall rule')
    ssh_client.exec_command("uci set firewall.@rule[-1].src='wan'")
    ssh_client.exec_command("uci set firewall.@rule[-1].target='ACCEPT'")
    ssh_client.exec_command("uci set firewall.@rule[-1].proto='udp'")
    ssh_client.exec_command("uci set firewall.@rule[-1].dest_port='1516'")
    ssh_client.exec_command("uci set firewall.@rule[-1].name='IFM'")
    ssh_client.exec_command("uci commit firewall")
    ssh_client.exec_command("reload_config")
    
