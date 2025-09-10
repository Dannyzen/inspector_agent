import os
import signal

class Remediation:
    def kill_process(self, pid):
        """
        Kills a process by its PID.
        """
        try:
            os.kill(int(pid), signal.SIGKILL)
            return True
        except OSError:
            return False

class ThreatAnalyzer:
    def __init__(self):
        self.known_threats = {
            "12345": {
                "name": "NetBus Trojan",
                "process_explanation": "nc (netcat) is a versatile networking utility used for reading from and writing to network connections.",
                "rationale": "The NetBus trojan, a remote administration tool, is known to use port 12345, making any process listening on this port suspicious."
            },
            "8083": {
                "name": "Simulated Threat",
                "process_explanation": "A simulated threat for demonstration purposes.",
                "rationale": "This process is listening on a port designated for a threat simulation."
            }
        }
        self.process_descriptions = {
            "nc": "nc (netcat) is a versatile networking utility used for reading from and writing to network connections.",
            "python": "Python is a high-level, general-purpose programming language.",
            "sshd": "sshd (OpenSSH Daemon) is the daemon program for ssh.",
            "code": "Visual Studio Code is a code editor redefined and optimized for building and debugging modern web and cloud applications.",
        }
        self.remediation = Remediation()

    def analyze(self, command, port):
        """
        Analyzes a process to determine if it's a known threat and provides an explanation.
        """
        port_str = str(port)
        if port_str in self.known_threats:
            threat_info = self.known_threats[port_str]
            return {
                "is_threat": True,
                "process_explanation": threat_info["process_explanation"],
                "rationale": threat_info["rationale"]
            }

        if "nc" in command and "-e" in command:
            return {
                "is_threat": True,
                "process_explanation": "The '-e' flag in netcat can be used to execute a program upon connection, which is a common technique for creating reverse shells.",
                "rationale": "This command is characteristic of a reverse shell, which can grant an attacker remote access to the system."
            }
        
        process_name = command.split()[0]
        process_explanation = self.process_descriptions.get(process_name, "This is a standard network listening process.")

        return {
            "is_threat": False,
            "process_explanation": process_explanation,
            "rationale": "No specific threat indicators were found for this process."
        }