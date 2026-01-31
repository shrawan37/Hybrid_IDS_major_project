import subprocess
import sys
import logging

class ActiveResponse:
    def __init__(self):
        self.blocked_ips = set()
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("ActiveResponse")

    def block_ip(self, ip_address):
        """
        Block an IP address using Windows Firewall (requires Admin privileges).
        """
        if ip_address in self.blocked_ips:
            return False, "IP already blocked"

        # Prevent blocking localhost or internal 
        if ip_address.startswith("127.") or ip_address.startswith("192.168."):
             return False, "Cannot block internal/localhost IP"

        rule_name = f"IDS_BLOCK_{ip_address}"
        
        # Command to add firewall rule
        # netsh advfirewall firewall add rule name="IDS_BLOCK_1.2.3.4" dir=in action=block remoteip=1.2.3.4
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}"
        ]

        try:
            # Hide console window
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW # Hides window
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, startupinfo=startupinfo)
            self.blocked_ips.add(ip_address)
            self.logger.info(f"Blocked IP: {ip_address}")
            return True, f"Successfully blocked {ip_address}"
        
        except subprocess.CalledProcessError as e:
            err_msg = f"Failed to block IP: {e.stderr}"
            self.logger.error(err_msg)
            return False, err_msg
        except Exception as e:
            return False, str(e)

    def unblock_ip(self, ip_address):
        """Remove the blocking rule."""
        rule_name = f"IDS_BLOCK_{ip_address}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.run(cmd, check=True, startupinfo=startupinfo)
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
            return True, f"Unblocked {ip_address}"
        except Exception as e:
            return False, str(e)
