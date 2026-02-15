"""
ThreatOps Log Simulator
Generates realistic security event logs with MITRE ATT&CK and D3FEND mappings
"""

import random
from datetime import datetime, timedelta
from typing import List, Dict, Tuple


class ThreatSimulator:
    """Simulates realistic attack scenarios with MITRE mappings."""
    
    # Internal IP ranges for corporate networks
    INTERNAL_IPS = [
        f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        for _ in range(50)
    ]
    
    # External threat actor IPs (simulated)
    EXTERNAL_IPS = [
        f"{random.randint(45, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
        for _ in range(30)
    ]
    
    # Attack scenario templates
    ATTACK_SCENARIOS = {
        "Brute Force": {
            "protocols": ["SSH", "RDP", "FTP", "SMTP"],
            "descriptions": [
                "Multiple failed login attempts from {source_ip}",
                "Brute force attack detected on {protocol} service",
                "Failed authentication attempts: {count} in 60 seconds",
                "Password spraying attack against user accounts",
                "Credential stuffing attempt detected",
            ],
            "severity": "high",
            "frequency": 0.15,
        },
        "Port Scan": {
            "protocols": ["TCP", "UDP", "ICMP"],
            "descriptions": [
                "Port scanning activity detected from {source_ip}",
                "Nmap scan signature identified on ports 1-1024",
                "Reconnaissance: Sequential port probing detected",
                "Stealth SYN scan attempt from external IP",
                "Service enumeration via port scanning",
            ],
            "severity": "medium",
            "frequency": 0.12,
        },
        "Malware": {
            "protocols": ["HTTP", "HTTPS", "DNS", "SMB"],
            "descriptions": [
                "Malicious payload detected in HTTP traffic",
                "Trojan communication to C2 server at {source_ip}",
                "Suspicious executable downloaded: {filename}",
                "Ransomware encryption activity detected",
                "Backdoor installation attempt via SMB",
            ],
            "severity": "critical",
            "frequency": 0.10,
        },
        "Phishing": {
            "protocols": ["SMTP", "HTTP", "HTTPS"],
            "descriptions": [
                "Phishing email with malicious link detected",
                "Credential harvesting page accessed from {source_ip}",
                "Spear phishing attempt targeting {user}",
                "Malicious attachment opened: {filename}",
                "Email spoofing detected from external domain",
            ],
            "severity": "high",
            "frequency": 0.08,
        },
        "Data Exfiltration": {
            "protocols": ["HTTPS", "DNS", "FTP"],
            "descriptions": [
                "Large data transfer to external IP {source_ip}",
                "DNS tunneling detected: {size}MB exfiltrated",
                "Unusual outbound traffic volume detected",
                "Sensitive file upload to cloud storage",
                "Data exfiltration via encrypted channel",
            ],
            "severity": "critical",
            "frequency": 0.05,
        },
        "Privilege Escalation": {
            "protocols": ["RPC", "SMB", "WMI"],
            "descriptions": [
                "Unauthorized privilege elevation detected",
                "Exploit attempt: CVE-2021-{vuln_id}",
                "Sudo abuse detected on {hostname}",
                "Token manipulation for privilege escalation",
                "Kernel exploit attempt identified",
            ],
            "severity": "critical",
            "frequency": 0.07,
        },
        "DoS": {
            "protocols": ["TCP", "UDP", "ICMP", "HTTP"],
            "descriptions": [
                "DDoS attack detected: {pps} packets/sec",
                "SYN flood from {source_ip}",
                "HTTP flood targeting {endpoint}",
                "UDP amplification attack detected",
                "Service degradation due to resource exhaustion",
            ],
            "severity": "high",
            "frequency": 0.06,
        },
        "DNS Tunneling": {
            "protocols": ["DNS"],
            "descriptions": [
                "DNS tunneling detected: abnormal query volume",
                "C2 communication via DNS TXT records",
                "Suspicious DNS query pattern from {source_ip}",
                "Data exfiltration through DNS requests",
                "Encoded payload in DNS subdomain",
            ],
            "severity": "high",
            "frequency": 0.04,
        },
        "Ransomware": {
            "protocols": ["SMB", "RDP", "HTTP"],
            "descriptions": [
                "File encryption activity detected on {hostname}",
                "Ransomware note created: {filename}",
                "Mass file modification detected",
                "Shadow copy deletion attempt",
                "Backup deletion activity detected",
            ],
            "severity": "critical",
            "frequency": 0.03,
        },
        "Credential Dumping": {
            "protocols": ["SMB", "LDAP", "RPC"],
            "descriptions": [
                "LSASS memory dump attempt detected",
                "Mimikatz signature identified",
                "SAM database access detected",
                "Credential extraction from registry",
                "Password hash dumping activity",
            ],
            "severity": "critical",
            "frequency": 0.05,
        },
        "Remote Desktop Protocol": {
            "protocols": ["RDP"],
            "descriptions": [
                "Unauthorized RDP connection from {source_ip}",
                "RDP session established from unusual location",
                "Lateral movement via RDP detected",
                "RDP brute force followed by successful login",
                "Multiple concurrent RDP sessions detected",
            ],
            "severity": "medium",
            "frequency": 0.08,
        },
        "PowerShell": {
            "protocols": ["WMI", "SMB"],
            "descriptions": [
                "Suspicious PowerShell script execution",
                "Encoded PowerShell command detected",
                "PowerShell Empire framework signature",
                "Download cradle detected in PowerShell",
                "Fileless malware execution via PowerShell",
            ],
            "severity": "high",
            "frequency": 0.06,
        },
        "C2 Communication": {
            "protocols": ["HTTPS", "HTTP", "DNS"],
            "descriptions": [
                "Beaconing behavior detected to {source_ip}",
                "Command and Control callback identified",
                "C2 traffic to known malicious IP",
                "Cobalt Strike communication detected",
                "Periodic callback pattern to external server",
            ],
            "severity": "critical",
            "frequency": 0.07,
        },
    }
    
    def __init__(self):
        """Initialize the simulator."""
        self.generated_logs = []
    
    def generate_log_entry(
        self, 
        attack_type: str, 
        timestamp: datetime
    ) -> Dict[str, str]:
        """Generate a single log entry for the given attack type."""
        
        scenario = self.ATTACK_SCENARIOS[attack_type]
        
        # Select IPs based on attack type
        if attack_type in ["Data Exfiltration", "Port Scan", "Phishing", "C2 Communication"]:
            source_ip = random.choice(self.INTERNAL_IPS)
            dest_ip = random.choice(self.EXTERNAL_IPS)
        elif attack_type in ["Brute Force", "DoS"]:
            source_ip = random.choice(self.EXTERNAL_IPS)
            dest_ip = random.choice(self.INTERNAL_IPS)
        else:
            # Internal lateral movement
            source_ip = random.choice(self.INTERNAL_IPS)
            dest_ip = random.choice(self.INTERNAL_IPS)
        
        # Generate dynamic description
        description_template = random.choice(scenario["descriptions"])
        description = description_template.format(
            source_ip=source_ip,
            protocol=random.choice(scenario["protocols"]),
            count=random.randint(10, 500),
            filename=f"payload_{random.randint(1000, 9999)}.exe",
            user=f"user{random.randint(1, 50)}",
            size=random.randint(10, 1000),
            hostname=f"WS{random.randint(100, 999)}",
            vuln_id=random.randint(10000, 99999),
            pps=random.randint(10000, 500000),
            endpoint="/api/login",
        )
        
        return {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "protocol": random.choice(scenario["protocols"]),
            "event_description": description,
            "attack_type": attack_type,
        }
    
    def generate_attack_scenario(
        self, 
        num_logs: int = 100,
        time_span_hours: int = 24
    ) -> List[Dict[str, str]]:
        """
        Generate a realistic attack scenario with multiple log entries.
        
        Args:
            num_logs: Number of log entries to generate
            time_span_hours: Time span in hours to distribute logs
            
        Returns:
            List of log entry dictionaries
        """
        logs = []
        start_time = datetime.now() - timedelta(hours=time_span_hours)
        
        # Calculate log distribution based on attack frequencies
        attack_distribution = []
        for attack_type, scenario in self.ATTACK_SCENARIOS.items():
            count = int(num_logs * scenario["frequency"])
            attack_distribution.extend([attack_type] * count)
        
        # Fill remaining slots with random attacks
        while len(attack_distribution) < num_logs:
            attack_distribution.append(random.choice(list(self.ATTACK_SCENARIOS.keys())))
        
        # Shuffle to randomize order
        random.shuffle(attack_distribution)
        
        # Generate logs with incremental timestamps
        for i, attack_type in enumerate(attack_distribution[:num_logs]):
            # Create realistic time distribution (more attacks during business hours)
            hour_offset = (time_span_hours / num_logs) * i
            minutes_offset = random.randint(0, 59)
            seconds_offset = random.randint(0, 59)
            
            timestamp = start_time + timedelta(
                hours=hour_offset,
                minutes=minutes_offset,
                seconds=seconds_offset
            )
            
            log_entry = self.generate_log_entry(attack_type, timestamp)
            logs.append(log_entry)
        
        # Sort by timestamp
        logs.sort(key=lambda x: x["timestamp"])
        
        self.generated_logs = logs
        return logs
    
    def generate_targeted_attack(
        self, 
        attack_chain: List[str],
        num_logs_per_stage: int = 10
    ) -> List[Dict[str, str]]:
        """
        Generate a targeted attack following the cyber kill chain.
        
        Args:
            attack_chain: List of attack types in sequence (e.g., reconnaissance -> weaponization -> delivery)
            num_logs_per_stage: Number of logs for each attack stage
            
        Returns:
            List of log entries representing the attack chain
        """
        logs = []
        start_time = datetime.now() - timedelta(hours=len(attack_chain))
        
        for stage_idx, attack_type in enumerate(attack_chain):
            stage_start = start_time + timedelta(hours=stage_idx)
            
            for log_idx in range(num_logs_per_stage):
                timestamp = stage_start + timedelta(
                    minutes=log_idx * (60 / num_logs_per_stage)
                )
                log_entry = self.generate_log_entry(attack_type, timestamp)
                logs.append(log_entry)
        
        return logs
    
    def get_attack_statistics(self) -> Dict[str, int]:
        """Get statistics about generated attack logs."""
        if not self.generated_logs:
            return {}
        
        stats = {}
        for log in self.generated_logs:
            attack_type = log["attack_type"]
            stats[attack_type] = stats.get(attack_type, 0) + 1
        
        return stats


# Predefined attack chains for realistic scenarios
ATTACK_CHAINS = {
    "APT_Campaign": [
        "Phishing",
        "Malware",
        "Privilege Escalation",
        "Credential Dumping",
        "Remote Desktop Protocol",
        "Data Exfiltration",
    ],
    "Ransomware_Attack": [
        "Phishing",
        "PowerShell",
        "Credential Dumping",
        "Remote Desktop Protocol",
        "Ransomware",
    ],
    "Insider_Threat": [
        "Credential Dumping",
        "Data from Local System",
        "Data Exfiltration",
    ],
    "DDoS_Campaign": [
        "Port Scan",
        "DoS",
    ],
}
