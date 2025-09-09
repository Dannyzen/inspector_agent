class ThreatAnalyzer:
    def __init__(self):
        self.known_threats = {
            "12345": {
                "name": "NetBus Trojan",
                "process_explanation": "nc (netcat) is a versatile networking utility used for reading from and writing to network connections.",
                "rationale": "The NetBus trojan, a remote administration tool, is known to use port 12345, making any process listening on this port suspicious."
            }
        }

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
        
        return {
            "is_threat": False,
            "process_explanation": "This is a standard network listening process.",
            "rationale": "No specific threat indicators were found for this process."
        }