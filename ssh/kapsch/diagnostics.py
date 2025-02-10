import logging
import os
import re

from ... import ssh

from ... import connection
from . import connect



@connection.add_method(connect.KapschConnection)
def get_cv2x_rx_packets(target, trace_time=2, output='string', conn_args={}):
    """Pull a trace of the packets on the CV2X radio. trace_time= is in seconds"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        cv2x_cmd = ssh_conn.sudo("timeout {} tcpdump -i rmnet_data1 -n -x -e port 9000".format(trace_time), warn=True, hide=True)

    return _format_packets(cv2x_cmd)


@connection.add_method(connect.KapschConnection)
def get_cv2x_tx_packets(target, trace_time=2, output='string', conn_args={}):
    """Pull a trace of the packets on the CV2X radio. trace_time= is in seconds"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        cv2x_cmd = ssh_conn.sudo("timeout {} tcpdump -i rmnet_data1 -n -x -e port 2602".format(trace_time), warn=True, hide=True)

    return _format_packets(cv2x_cmd)


@connection.add_method(connect.KapschConnection)
def get_dsrc_rx_packets(target, trace_time=2, radio="a", output='string', conn_args={}):
    """Pull a trace of the packets on the DSRC radio. trace_time= is in seconds.
    radio='a' or 'b' depending on which channels/radio to trace"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        if not (radio.lower() == 'a' or radio.lower() == 'b'):
            raise TypeError("radio= must be either 'a' or 'b")

        dsrc_cmd = ssh_conn.sudo("timeout {to} tcpdump -i cw-mon-rx{rdo} -n -x -e".format(to=trace_time, rdo=radio), warn=True)

    return _format_packets(dsrc_cmd)


@connection.add_method(connect.KapschConnection)
def get_dsrc_tx_packets(target, trace_time=2, radio="a", output='string', conn_args={}):
    """Pull a trace of the packets on the DSRC radio. trace_time= is in seconds.
    radio='a' or 'b' depending on which channels/radio to trace"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        if not (radio.lower() == 'a' or radio.lower() == 'b'):
            raise TypeError("radio= must be either 'a' or 'b")

        dsrc_cmd = ssh_conn.sudo("timeout {to} tcpdump -i cw-mon-tx{rdo} -n -x -e".format(to=trace_time, rdo=radio), warn=True)

    return _format_packets(dsrc_cmd)


@connection.add_method(connect.KapschConnection)
def get_eth_packets(target, port:int, trace_time=2, output='string', conn_args={}):
    """Trace Ethernet packets. trace_time= is in seconds. 
    port= UDP or TCP port number to trace"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        eth_cmd = ssh_conn.sudo("timeout {to} tcpdump -i eth0 -n -x -e port {prt}".format(to=trace_time, prt=port), warn=True)

    return _format_packets(eth_cmd)


@connection.add_method(connect.KapschConnection)
def get_rsu_log(target, local=None, conn_args={}):
    """Pull the RSU log. If local=None, will save log to variable. 
    If local is given a folder/path, will save it to a file rsu.log at that location"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:

        if local is None:
            log_cmd = ssh_conn.run('cat /var/log/kapsch-rsu/rsu.log', hide=True, warn=True)
            if log_cmd.return_code == 0:
                return log_cmd.stdout
            else:
                logging.error("Failed to get RSU log:\nCode: {rtc}\nStdErr: {err}".format(rtc=log_cmd.return_code, err=log_cmd.stderr))
                raise FileNotFoundError
        else:
            ssh_conn.get('/var/log/kapsch-rsu/rsu.log', local=local)
            return os.path.abspath(local)


@connection.add_method(connect.KapschConnection)
def get_security_log(target, conn_args={}):
    """Pull the aerolink log"""

    with ssh.SshChecker(target, conn_args) as ssh_conn:
        pass


def _format_packets(cmd_out, format_type='s'):
    """Turn the raw string output into a useful packet format"""

    # TODO: Allow multiple types (list, human-readable, etc)??
    # TODO: how to set PCAP output # tcpdump -pi eth0 port 161 -s0 -w /tmp/snmpdump.pcap -v

    # types:
    # s / string            ---> tcpdump output as is (string)
    # d / dict / dictionary ---> dict, with keys 'time', 'data', and maybe 'type' (TIM, MAP, ETC)
    # l / list              ---> packets, separated into list of strings
    # p / pcap / raw        ---> PCAP output

    # TODO: timeout command always returns code 124; using empty stdout to detect;see if there's a better way

    if cmd_out.stdout == '\n':
        return 'No data'
    
    elif "No such device exists" in cmd_out.stderr :
        logging.warn("Failed to find specified device:\nCode: {rtc}\nStdErr: {err}\nCommand: {cmd}".format(
                        rtc=cmd_out.return_code, err=cmd_out.stderr, cmd=cmd_out.command))
        return 'No interface'
    
    else:
        # TODO: Figure out how to split packets
        if format_type.lower() == 's' or format_type.lower() == 'string':
            return cmd_out.stdout
        elif format_type.lower() == 'l' or format_type.lower() == 'list':
            logging.warning("Output type 'list' not yet supported. Returning 'string'")
            return cmd_out.stdout
        elif format_type.lower() == 'd' or format_type.lower() == 'dict' or format_type.lower() == 'dictionary':
            logging.warning("Output type 'dict' not yet supported. Returning 'string'")
            return cmd_out.stdout
        elif format_type.lower() == 'p' or format_type.lower() == 'pcap' or format_type.lower() == 'raw':
            logging.warning("Output type 'pcap' not yet supported. Returning 'string'")
            return cmd_out.stdout
        else:
            # TODO: add any other format types
            logging.error("Unknown value for output/format_Type: {}\n Valid types are 'dict', 'string', 'list', or 'pcap'.".format(format_type))
            raise TypeError
