# firewall_blocker.py
import subprocess
import platform
from logger import log_intrusion, log_block

def _run_cmd(cmd):
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return completed.returncode, completed.stdout + completed.stderr
    except Exception as e:
        return -1, str(e)

def block_ip(ip_address: str):
    """
    Cross-platform attempt to block an IP. On Windows uses netsh; on Linux uses iptables.
    Idempotent-ish: if the system repeats the rule, Windows will allow duplicates - we log once.
    Must be run with appropriate privileges.
    """
    system = platform.system()

    if system == "Windows":
        rule_name = f"PyGuardian_Block_{ip_address}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]
        code, output = _run_cmd(cmd)
        if code == 0:
            log_block(ip_address)
            return True
        else:
            log_intrusion(f"[ERROR] Blocking {ip_address} failed: {output}")
            return False

    else:
        # Linux
        cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        code, out = _run_cmd(cmd)
        if code == 0:
            # Rule already exists
            log_intrusion(f"[INFO] iptables rule for {ip_address} already present")
            return True

        # add the rule
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        code, output = _run_cmd(cmd)
        if code == 0:
            log_block(ip_address)
            return True
        else:
            log_intrusion(f"[ERROR] iptables add failed for {ip_address}: {output}")
            return False
