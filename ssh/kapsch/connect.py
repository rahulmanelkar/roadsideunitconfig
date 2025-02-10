from ... import ssh


class KapschConnection(ssh.Connection):
    """Create a Kapsch sub-class of connection. This gets created on object creation to allow
    rsu_toolkit.connection.add_method to work conditionally on vendors"""

    def __init__(self, target_ip, user='admin', pw='admin', sudo_pw="admin", priv_key=None, gateway=None):
        super().__init__(target_ip, user=user, pw=pw, sudo_pw=sudo_pw, priv_key=priv_key, gateway=gateway)