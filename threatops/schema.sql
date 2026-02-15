-- ThreatOps SIEM Database Schema
-- Strictly following DBMS Report Chapter 2

DROP DATABASE IF EXISTS threatops;
CREATE DATABASE threatops;
USE threatops;

-- ================================================================
-- TABLE 1: USERS (Authentication & RBAC)
-- ================================================================
CREATE TABLE USERS (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin', 'Analyst', 'Manager', 'Engineer', 'Responder', 'Hunter') NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- ================================================================
-- TABLE 2: RAW_LOGS (Raw Security Event Data)
-- ================================================================
CREATE TABLE RAW_LOGS (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    protocol ENUM('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'RDP', 'SMB', 'WMI', 'RPC', 'LDAP') NOT NULL,
    port INT CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    event_description TEXT NOT NULL,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    uploaded_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploaded_by) REFERENCES USERS(user_id) ON DELETE SET NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_source_ip (source_ip)
);

-- ================================================================
-- TABLE 3: MITRE_ATTACK_TECHNIQUES (ATT&CK Framework)
-- ================================================================
CREATE TABLE MITRE_ATTACK_TECHNIQUES (
    technique_id VARCHAR(50) PRIMARY KEY,
    technique_name VARCHAR(255) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    description TEXT,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    INDEX idx_tactic (tactic)
);

-- ================================================================
-- TABLE 4: MITRE_DEFEND_COUNTERMEASURES (D3FEND Framework)
-- ================================================================
CREATE TABLE MITRE_DEFEND_COUNTERMEASURES (
    countermeasure_id VARCHAR(50) PRIMARY KEY,
    countermeasure_name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT,
    implementation_cost DECIMAL(10, 2) CHECK (implementation_cost >= 0),
    effectiveness_rating ENUM('Low', 'Medium', 'High', 'Very High') NOT NULL
);

-- ================================================================
-- TABLE 5: THREAT_CORRELATION (Links Logs to MITRE Frameworks)
-- ================================================================
CREATE TABLE THREAT_CORRELATION (
    correlation_id INT PRIMARY KEY AUTO_INCREMENT,
    log_id INT NOT NULL,
    technique_id VARCHAR(50) NOT NULL,
    countermeasure_id VARCHAR(50),
    confidence_score DECIMAL(3, 2) CHECK (confidence_score BETWEEN 0 AND 1),
    correlated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    correlated_by INT,
    FOREIGN KEY (log_id) REFERENCES RAW_LOGS(log_id) ON DELETE CASCADE,
    FOREIGN KEY (technique_id) REFERENCES MITRE_ATTACK_TECHNIQUES(technique_id),
    FOREIGN KEY (countermeasure_id) REFERENCES MITRE_DEFEND_COUNTERMEASURES(countermeasure_id),
    FOREIGN KEY (correlated_by) REFERENCES USERS(user_id) ON DELETE SET NULL,
    INDEX idx_log_id (log_id),
    INDEX idx_technique (technique_id)
);

-- ================================================================
-- TABLE 6: ALERTS (Generated Threat Alerts)
-- ================================================================
CREATE TABLE ALERTS (
    alert_id INT PRIMARY KEY AUTO_INCREMENT,
    correlation_id INT NOT NULL,
    alert_type ENUM('Intrusion', 'Data Breach', 'Malware', 'DDoS', 'Privilege Escalation', 'Reconnaissance') NOT NULL,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
    status ENUM('Open', 'In Progress', 'Resolved', 'False Positive') DEFAULT 'Open',
    assigned_to INT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (correlation_id) REFERENCES THREAT_CORRELATION(correlation_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to) REFERENCES USERS(user_id) ON DELETE SET NULL,
    INDEX idx_status (status),
    INDEX idx_severity (severity),
    INDEX idx_created (created_at)
);

-- ================================================================
-- TABLE 7: AUDIT_LOGS (System Audit Trail)
-- ================================================================
CREATE TABLE AUDIT_LOGS (
    audit_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action_type ENUM('LOGIN', 'LOGOUT', 'QUERY_EXECUTION', 'CSV_UPLOAD', 'ALERT_CREATION', 'USER_MANAGEMENT', 'DATA_MODIFICATION') NOT NULL,
    action_details TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('Success', 'Failure') DEFAULT 'Success',
    FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE SET NULL,
    INDEX idx_user (user_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_action (action_type)
);

-- ================================================================
-- INSERT SOC/CIRT TEAM USERS
-- Role-Based Passwords: ADM123 (Admin), ANLST123 (Analyst), MGR123 (Manager), 
--                       ENG123 (Engineer), RESP123 (Responder), HUNT123 (Hunter)
-- ================================================================
INSERT INTO USERS (username, password_hash, role, email, created_at, last_login, is_active) VALUES
-- Administrators
('rajesh_kumar', SHA2('ADM123', 256), 'Admin', 'rajesh.kumar@threatops.local', '2026-01-01 08:00:00', '2026-02-15 09:30:00', TRUE),
('deepak_verma', SHA2('ADM123', 256), 'Admin', 'deepak.verma@threatops.local', '2026-01-02 09:00:00', '2026-02-14 18:00:00', TRUE),

-- SOC Manager
('priya_sharma', SHA2('MGR123', 256), 'Manager', 'priya.sharma@threatops.local', '2026-01-01 08:15:00', '2026-02-15 10:00:00', TRUE),

-- Security Analysts
('amit_patel', SHA2('ANLST123', 256), 'Analyst', 'amit.patel@threatops.local', '2026-01-05 10:00:00', '2026-02-14 16:20:00', TRUE),
('sneha_singh', SHA2('ANLST123', 256), 'Analyst', 'sneha.singh@threatops.local', '2026-01-10 11:30:00', '2026-02-15 07:15:00', TRUE),
('rohan_gupta', SHA2('ANLST123', 256), 'Analyst', 'rohan.gupta@threatops.local', '2026-01-15 14:00:00', '2026-02-13 10:30:00', TRUE),
('meera_krishnan', SHA2('ANLST123', 256), 'Analyst', 'meera.krishnan@threatops.local', '2026-01-18 09:30:00', '2026-02-12 14:45:00', TRUE),

-- Security Engineers
('arjun_reddy', SHA2('ENG123', 256), 'Engineer', 'arjun.reddy@threatops.local', '2026-01-08 08:30:00', '2026-02-14 15:00:00', TRUE),
('vikram_desai', SHA2('ENG123', 256), 'Engineer', 'vikram.desai@threatops.local', '2026-01-12 13:00:00', '2026-02-13 11:30:00', TRUE),

-- Incident Responders (CIRT Team)
('kavya_iyer', SHA2('RESP123', 256), 'Responder', 'kavya.iyer@threatops.local', '2026-01-06 16:00:00', '2026-02-15 08:45:00', TRUE),
('sanjay_rao', SHA2('RESP123', 256), 'Responder', 'sanjay.rao@threatops.local', '2026-01-14 10:30:00', '2026-02-11 16:20:00', TRUE),

-- Threat Hunter
('ananya_nair', SHA2('HUNT123', 256), 'Hunter', 'ananya.nair@threatops.local', '2026-01-10 15:00:00', '2026-02-14 12:00:00', TRUE),

-- Inactive User (for testing)
('inactive_user', SHA2('ANLST123', 256), 'Analyst', 'inactive@threatops.local', '2026-01-01 08:00:00', '2026-01-05 10:00:00', FALSE);

-- ================================================================
-- POPULATE MITRE ATT&CK TECHNIQUES
-- ================================================================
INSERT INTO MITRE_ATTACK_TECHNIQUES (technique_id, technique_name, tactic, description, severity) VALUES
('T1110', 'Brute Force', 'Credential Access', 'Adversaries may use brute force techniques to gain access', 'High'),
('T1046', 'Network Service Scanning', 'Discovery', 'Adversaries may attempt to scan network services', 'Medium'),
('T1499', 'Endpoint Denial of Service', 'Impact', 'Adversaries may perform DoS attacks', 'High'),
('T1059', 'Command and Scripting Interpreter', 'Execution', 'Adversaries may abuse command interpreters', 'High'),
('T1566', 'Phishing', 'Initial Access', 'Adversaries may send phishing messages', 'Critical'),
('T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration', 'Adversaries may steal data via non-standard protocols', 'Critical'),
('T1068', 'Exploitation for Privilege Escalation', 'Privilege Escalation', 'Adversaries may exploit vulnerabilities to escalate privileges', 'Critical'),
('T1003', 'OS Credential Dumping', 'Credential Access', 'Adversaries may dump credentials from OS', 'Critical'),
('T1021.001', 'Remote Desktop Protocol', 'Lateral Movement', 'Adversaries may use RDP for lateral movement', 'Medium'),
('T1071.004', 'DNS Tunneling', 'Command and Control', 'Adversaries may use DNS for C2 communication', 'High'),
('T1486', 'Data Encrypted for Impact', 'Impact', 'Adversaries may encrypt data for ransom', 'Critical'),
('T1059.001', 'PowerShell', 'Execution', 'Adversaries may abuse PowerShell', 'High');

-- ================================================================
-- POPULATE MITRE D3FEND COUNTERMEASURES
-- ================================================================
INSERT INTO MITRE_DEFEND_COUNTERMEASURES (countermeasure_id, countermeasure_name, category, description, implementation_cost, effectiveness_rating) VALUES
('D3-AL', 'Authentication Logging', 'Detect', 'Log authentication events', 400000.00, 'High'),
('D3-NTA', 'Network Traffic Analysis', 'Detect', 'Analyze network traffic patterns', 1250000.00, 'Very High'),
('D3-RTF', 'Rate Limiting / Traffic Filtering', 'Harden', 'Limit traffic rate to prevent DoS', 660000.00, 'High'),
('D3-EXP', 'Execution Prevention', 'Isolate', 'Prevent unauthorized code execution', 1000000.00, 'Very High'),
('D3-EAL', 'Email Analysis', 'Detect', 'Analyze emails for threats', 830000.00, 'High'),
('D3-DLP', 'Data Loss Prevention', 'Harden', 'Prevent unauthorized data exfiltration', 1650000.00, 'Very High'),
('D3-PAM', 'Privilege Access Management', 'Harden', 'Control privileged access', 1500000.00, 'Very High'),
('D3-CH', 'Credential Hardening', 'Harden', 'Strengthen credential security', 580000.00, 'High'),
('D3-TF', 'Traffic Filtering', 'Isolate', 'Filter network traffic', 750000.00, 'High'),
('D3-DNSTA', 'DNS Traffic Analysis', 'Detect', 'Analyze DNS queries', 910000.00, 'High'),
('D3-BDU', 'Backup and Recovery', 'Restore', 'Implement backup systems', 2000000.00, 'Very High'),
('D3-PSA', 'PowerShell Script Analysis', 'Detect', 'Analyze PowerShell scripts', 500000.00, 'Medium');

-- ================================================================
-- POPULATE RAW_LOGS (Sample Security Event Data)
-- ================================================================
INSERT INTO RAW_LOGS (timestamp, source_ip, destination_ip, protocol, port, event_description, severity, uploaded_by) VALUES
('2026-02-14 08:15:23', '192.168.1.105', '10.0.0.50', 'SSH', 22, 'Multiple failed login attempts detected - brute force attack suspected from external IP', 'Critical', 2),
('2026-02-14 09:30:45', '172.16.0.88', '192.168.1.1', 'TCP', 8080, 'Port scanning activity detected - nmap fingerprint identified', 'High', 2),
('2026-02-14 10:45:12', '203.0.113.42', '10.0.0.100', 'UDP', 53, 'Unusual DNS query volume - potential DNS tunneling for command and control', 'High', 3),
('2026-02-14 11:20:33', '192.168.5.75', '10.0.0.75', 'HTTP', 80, 'SQL injection attempt in web application login form', 'Critical', 2),
('2026-02-14 12:05:18', '10.1.1.200', '192.168.1.50', 'SMB', 445, 'Suspicious file transfer - potential data exfiltration via SMB protocol', 'High', 4),
('2026-02-14 13:40:55', '172.31.10.15', '10.0.0.20', 'HTTPS', 443, 'Malware signature detected in encrypted traffic - trojan backdoor identified', 'Critical', 2),
('2026-02-14 14:25:07', '192.168.2.130', '10.0.0.5', 'RDP', 3389, 'Unauthorized RDP connection attempt from suspicious geographical location', 'Medium', 5),
('2026-02-14 15:10:42', '10.5.5.88', '192.168.1.100', 'TCP', 1433, 'Database credential dumping attempt using mimikatz-like tool', 'Critical', 3),
('2026-02-14 16:35:29', '198.51.100.77', '10.0.0.200', 'ICMP', NULL, 'DDoS attack detected - ICMP flood from multiple source addresses', 'Critical', 2),
('2026-02-14 17:50:11', '192.168.3.45', '10.0.0.150', 'DNS', 53, 'Phishing email with malicious link detected in email gateway logs', 'High', 4),
('2026-02-14 18:15:36', '172.20.5.99', '10.0.0.80', 'HTTPS', 443, 'Privilege escalation exploit attempt targeting kernel vulnerability CVE-2024-1234', 'Critical', 2),
('2026-02-14 19:22:48', '10.10.10.50', '192.168.1.75', 'TCP', 445, 'Ransomware encryption activity detected - multiple file modifications', 'Critical', 3),
('2026-02-14 20:05:19', '192.168.4.120', '10.0.0.30', 'TCP', 4444, 'Suspicious PowerShell script execution - obfuscated command detected', 'High', 2),
('2026-02-15 07:30:22', '203.0.113.88', '10.0.0.90', 'HTTP', 8080, 'Web application vulnerability scan detected - automated tool signatures', 'Medium', 5),
('2026-02-15 08:45:33', '192.168.1.200', '10.0.0.110', 'SMTP', 25, 'Spam campaign originating from compromised internal host', 'Medium', 2),
('2026-02-15 09:10:44', '172.18.0.55', '10.0.0.60', 'SSH', 22, 'Failed login attempts with default credentials - IoT device compromise attempt', 'High', 4),
('2026-02-15 10:25:55', '10.20.30.40', '192.168.1.150', 'TCP', 3306, 'MySQL database accessed from unauthorized IP address', 'High', 3),
('2026-02-15 11:40:12', '198.51.100.99', '10.0.0.180', 'UDP', 161, 'SNMP enumeration detected - reconnaissance activity', 'Low', 2),
('2026-02-15 12:55:28', '192.168.6.77', '10.0.0.70', 'LDAP', 389, 'LDAP injection attempt in authentication mechanism', 'High', 5),
('2026-02-15 13:20:45', '172.25.0.100', '10.0.0.120', 'RPC', 135, 'Remote procedure call exploit attempt - lateral movement suspected', 'Critical', 2);

-- ================================================================
-- POPULATE THREAT_CORRELATION (Link Logs to MITRE Techniques)
-- ================================================================
INSERT INTO THREAT_CORRELATION (log_id, technique_id, countermeasure_id, confidence_score, correlated_at, correlated_by) VALUES
(1, 'T1110', 'D3-AL', 0.95, '2026-02-14 08:16:00', 1),
(2, 'T1046', 'D3-NTA', 0.88, '2026-02-14 09:31:15', 1),
(3, 'T1071.004', 'D3-DNSTA', 0.92, '2026-02-14 10:46:00', 1),
(4, 'T1059', 'D3-EXP', 0.85, '2026-02-14 11:21:10', 1),
(5, 'T1048', 'D3-DLP', 0.90, '2026-02-14 12:06:00', 1),
(6, 'T1059', 'D3-EXP', 0.93, '2026-02-14 13:41:30', 1),
(7, 'T1021.001', 'D3-TF', 0.78, '2026-02-14 14:25:45', 1),
(8, 'T1003', 'D3-CH', 0.96, '2026-02-14 15:11:20', 1),
(9, 'T1499', 'D3-RTF', 0.97, '2026-02-14 16:36:00', 1),
(10, 'T1566', 'D3-EAL', 0.91, '2026-02-14 17:51:00', 1),
(11, 'T1068', 'D3-PAM', 0.94, '2026-02-14 18:16:15', 1),
(12, 'T1486', 'D3-BDU', 0.98, '2026-02-14 19:23:30', 1),
(13, 'T1059.001', 'D3-PSA', 0.87, '2026-02-14 20:06:00', 1),
(14, 'T1046', 'D3-NTA', 0.82, '2026-02-15 07:31:00', 1),
(15, 'T1566', 'D3-EAL', 0.75, '2026-02-15 08:46:15', 1),
(16, 'T1110', 'D3-AL', 0.89, '2026-02-15 09:11:30', 1),
(17, 'T1110', 'D3-AL', 0.86, '2026-02-15 10:26:45', 1),
(18, 'T1046', 'D3-NTA', 0.70, '2026-02-15 11:41:00', 1),
(19, 'T1059', 'D3-EXP', 0.84, '2026-02-15 12:56:15', 1),
(20, 'T1021.001', 'D3-TF', 0.81, '2026-02-15 13:21:30', 1);

-- ================================================================
-- POPULATE ALERTS (Generated Security Alerts)
-- ================================================================
INSERT INTO ALERTS (correlation_id, alert_type, severity, status, assigned_to, description, created_at, resolved_at) VALUES
(1, 'Intrusion', 'Critical', 'Resolved', 2, 'ALERT: Brute Force attack detected - Multiple failed SSH login attempts from 192.168.1.105', '2026-02-14 08:17:00', '2026-02-14 10:30:00'),
(2, 'Reconnaissance', 'High', 'Resolved', 3, 'ALERT: Network Service Scanning - Port scan detected from 172.16.0.88', '2026-02-14 09:32:00', '2026-02-14 14:20:00'),
(3, 'Reconnaissance', 'High', 'In Progress', 2, 'ALERT: DNS Tunneling detected - Unusual DNS traffic patterns from 203.0.113.42', '2026-02-14 10:47:00', NULL),
(4, 'Malware', 'Critical', 'Open', 4, 'ALERT: Command and Scripting Interpreter - SQL injection attempt in web application', '2026-02-14 11:22:00', NULL),
(5, 'Data Breach', 'High', 'In Progress', 2, 'ALERT: Data Exfiltration - Suspicious file transfer via SMB from 10.1.1.200', '2026-02-14 12:07:00', NULL),
(6, 'Malware', 'Critical', 'Resolved', 3, 'ALERT: Trojan backdoor detected in encrypted HTTPS traffic', '2026-02-14 13:42:00', '2026-02-14 16:45:00'),
(7, 'Intrusion', 'Medium', 'False Positive', 5, 'ALERT: Unauthorized RDP connection - Legitimate user from remote location', '2026-02-14 14:26:00', '2026-02-14 15:00:00'),
(8, 'Intrusion', 'Critical', 'In Progress', 2, 'ALERT: Credential Dumping - Mimikatz-like tool detected attempting to extract credentials', '2026-02-14 15:12:00', NULL),
(9, 'DDoS', 'Critical', 'Resolved', 1, 'ALERT: Distributed Denial of Service - ICMP flood attack mitigated', '2026-02-14 16:37:00', '2026-02-14 17:15:00'),
(10, 'Intrusion', 'High', 'Resolved', 4, 'ALERT: Phishing attack detected - Malicious email blocked by gateway', '2026-02-14 17:52:00', '2026-02-14 19:30:00'),
(11, 'Privilege Escalation', 'Critical', 'Open', 1, 'ALERT: Privilege Escalation - Kernel exploit attempt CVE-2024-1234', '2026-02-14 18:17:00', NULL),
(12, 'Malware', 'Critical', 'Open', 2, 'ALERT: Ransomware Activity - File encryption detected on multiple systems', '2026-02-14 19:24:00', NULL),
(13, 'Malware', 'High', 'In Progress', 3, 'ALERT: PowerShell Script Execution - Obfuscated malicious script detected', '2026-02-14 20:07:00', NULL),
(14, 'Reconnaissance', 'Medium', 'Resolved', 5, 'ALERT: Web Application Scan - Automated vulnerability scanning tool detected', '2026-02-15 07:32:00', '2026-02-15 09:00:00'),
(15, 'Intrusion', 'Medium', 'Open', 2, 'ALERT: Spam Campaign - Compromised internal host sending spam emails', '2026-02-15 08:47:00', NULL);

-- ================================================================
-- POPULATE AUDIT_LOGS (System Activity Audit Trail)
-- ================================================================
INSERT INTO AUDIT_LOGS (user_id, action_type, action_details, ip_address, timestamp, status) VALUES
(1, 'LOGIN', 'Admin user logged in successfully', '192.168.1.10', '2026-02-14 08:00:00', 'Success'),
(2, 'LOGIN', 'Analyst user logged in successfully', '192.168.1.15', '2026-02-14 08:05:00', 'Success'),
(1, 'QUERY_EXECUTION', 'Executed query: SELECT * FROM THREAT_INTELLIGENCE_DASHBOARD', '192.168.1.10', '2026-02-14 08:30:00', 'Success'),
(2, 'CSV_UPLOAD', 'Uploaded CSV file with 10 security logs', '192.168.1.15', '2026-02-14 09:00:00', 'Success'),
(1, 'USER_MANAGEMENT', 'Created new analyst user: john_doe', '192.168.1.10', '2026-02-14 09:30:00', 'Success'),
(3, 'LOGIN', 'Analyst john_doe logged in successfully', '192.168.1.20', '2026-02-14 10:00:00', 'Success'),
(2, 'QUERY_EXECUTION', 'Executed query: SELECT severity, COUNT(*) FROM RAW_LOGS GROUP BY severity', '192.168.1.15', '2026-02-14 10:15:00', 'Success'),
(1, 'DATA_MODIFICATION', 'Updated alert status from Open to Resolved for alert_id=1', '192.168.1.10', '2026-02-14 10:30:00', 'Success'),
(4, 'LOGIN', 'Analyst sarah_smith logged in successfully', '192.168.1.25', '2026-02-14 11:00:00', 'Success'),
(3, 'QUERY_EXECUTION', 'Executed query: SELECT * FROM ALERTS WHERE severity=Critical', '192.168.1.20', '2026-02-14 11:30:00', 'Success'),
(1, 'QUERY_EXECUTION', 'Executed DDL: CREATE INDEX idx_test ON RAW_LOGS(source_ip)', '192.168.1.10', '2026-02-14 12:00:00', 'Success'),
(2, 'ALERT_CREATION', 'Created new alert for correlation_id=5', '192.168.1.15', '2026-02-14 12:07:00', 'Success'),
(5, 'LOGIN', 'Admin mike_johnson logged in successfully', '192.168.1.30', '2026-02-14 13:00:00', 'Success'),
(4, 'QUERY_EXECUTION', 'Executed query: SELECT * FROM MITRE_ATTACK_TECHNIQUES', '192.168.1.25', '2026-02-14 13:30:00', 'Success'),
(5, 'DATA_MODIFICATION', 'Updated user permissions for user_id=3', '192.168.1.30', '2026-02-14 14:00:00', 'Success'),
(1, 'QUERY_EXECUTION', 'Executed query: SELECT * FROM USER_ACTIVITY_SUMMARY', '192.168.1.10', '2026-02-14 14:30:00', 'Success'),
(2, 'CSV_UPLOAD', 'Uploaded CSV file with 8 security logs', '192.168.1.15', '2026-02-14 15:00:00', 'Success'),
(3, 'QUERY_EXECUTION', 'Attempted DDL: DROP TABLE test_table', '192.168.1.20', '2026-02-14 15:30:00', 'Failure'),
(6, 'LOGIN', 'Analyst emma_wilson logged in successfully', '192.168.1.35', '2026-02-14 16:00:00', 'Success'),
(1, 'DATA_MODIFICATION', 'Updated alert status from In Progress to Resolved for alert_id=2', '192.168.1.10', '2026-02-14 16:30:00', 'Success'),
(4, 'LOGOUT', 'Analyst sarah_smith logged out', '192.168.1.25', '2026-02-14 17:00:00', 'Success'),
(2, 'QUERY_EXECUTION', 'Executed query: SELECT * FROM RAW_LOGS WHERE severity=Critical LIMIT 10', '192.168.1.15', '2026-02-14 17:30:00', 'Success'),
(5, 'USER_MANAGEMENT', 'Deactivated user account: inactive_user', '192.168.1.30', '2026-02-14 18:00:00', 'Success'),
(7, 'LOGIN', 'Analyst david_brown logged in successfully', '192.168.1.40', '2026-02-15 08:00:00', 'Success'),
(1, 'QUERY_EXECUTION', 'Executed query: SELECT * FROM AUDIT_LOGS ORDER BY timestamp DESC LIMIT 50', '192.168.1.10', '2026-02-15 08:30:00', 'Success');

-- ================================================================
-- VIEW 1: THREAT_INTELLIGENCE_DASHBOARD
-- ================================================================
CREATE VIEW THREAT_INTELLIGENCE_DASHBOARD AS
SELECT 
    rl.log_id,
    rl.timestamp,
    rl.source_ip,
    rl.destination_ip,
    rl.protocol,
    rl.severity AS log_severity,
    mat.technique_id,
    mat.technique_name,
    mat.tactic,
    mat.severity AS technique_severity,
    mdc.countermeasure_name,
    mdc.effectiveness_rating,
    tc.confidence_score,
    a.alert_type,
    a.status AS alert_status
FROM RAW_LOGS rl
LEFT JOIN THREAT_CORRELATION tc ON rl.log_id = tc.log_id
LEFT JOIN MITRE_ATTACK_TECHNIQUES mat ON tc.technique_id = mat.technique_id
LEFT JOIN MITRE_DEFEND_COUNTERMEASURES mdc ON tc.countermeasure_id = mdc.countermeasure_id
LEFT JOIN ALERTS a ON tc.correlation_id = a.correlation_id
ORDER BY rl.timestamp DESC;

-- ================================================================
-- VIEW 2: USER_ACTIVITY_SUMMARY
-- ================================================================
CREATE VIEW USER_ACTIVITY_SUMMARY AS
SELECT 
    u.user_id,
    u.username,
    u.role,
    COUNT(DISTINCT al.audit_id) AS total_actions,
    COUNT(DISTINCT CASE WHEN al.action_type = 'QUERY_EXECUTION' THEN al.audit_id END) AS queries_executed,
    COUNT(DISTINCT CASE WHEN al.action_type = 'CSV_UPLOAD' THEN al.audit_id END) AS files_uploaded,
    MAX(al.timestamp) AS last_activity
FROM USERS u
LEFT JOIN AUDIT_LOGS al ON u.user_id = al.user_id
GROUP BY u.user_id, u.username, u.role;

-- ================================================================
-- STORED PROCEDURE 1: CORRELATE_THREAT
-- Automatically correlate raw logs with MITRE techniques
-- ================================================================
DELIMITER //

CREATE PROCEDURE CORRELATE_THREAT(
    IN p_log_id INT,
    IN p_user_id INT
)
BEGIN
    DECLARE v_technique_id VARCHAR(50);
    DECLARE v_countermeasure_id VARCHAR(50);
    DECLARE v_confidence DECIMAL(3,2);
    DECLARE v_event_desc TEXT;
    DECLARE v_severity VARCHAR(20);
    
    -- Get log details
    SELECT event_description, severity INTO v_event_desc, v_severity
    FROM RAW_LOGS WHERE log_id = p_log_id;
    
    -- Pattern matching for threat correlation
    SET v_confidence = 0.75;
    
    IF v_event_desc LIKE '%brute%force%' OR v_event_desc LIKE '%failed%login%' THEN
        SET v_technique_id = 'T1110';
        SET v_countermeasure_id = 'D3-AL';
        SET v_confidence = 0.85;
    ELSEIF v_event_desc LIKE '%port%scan%' OR v_event_desc LIKE '%nmap%' THEN
        SET v_technique_id = 'T1046';
        SET v_countermeasure_id = 'D3-NTA';
        SET v_confidence = 0.80;
    ELSEIF v_event_desc LIKE '%dos%' OR v_event_desc LIKE '%flood%' THEN
        SET v_technique_id = 'T1499';
        SET v_countermeasure_id = 'D3-RTF';
        SET v_confidence = 0.90;
    ELSEIF v_event_desc LIKE '%malware%' OR v_event_desc LIKE '%trojan%' THEN
        SET v_technique_id = 'T1059';
        SET v_countermeasure_id = 'D3-EXP';
        SET v_confidence = 0.88;
    ELSEIF v_event_desc LIKE '%phishing%' OR v_event_desc LIKE '%spear%' THEN
        SET v_technique_id = 'T1566';
        SET v_countermeasure_id = 'D3-EAL';
        SET v_confidence = 0.92;
    ELSEIF v_event_desc LIKE '%exfiltration%' OR v_event_desc LIKE '%data%transfer%' THEN
        SET v_technique_id = 'T1048';
        SET v_countermeasure_id = 'D3-DLP';
        SET v_confidence = 0.87;
    ELSEIF v_event_desc LIKE '%privilege%escalation%' OR v_event_desc LIKE '%exploit%' THEN
        SET v_technique_id = 'T1068';
        SET v_countermeasure_id = 'D3-PAM';
        SET v_confidence = 0.91;
    ELSEIF v_event_desc LIKE '%credential%dump%' OR v_event_desc LIKE '%mimikatz%' THEN
        SET v_technique_id = 'T1003';
        SET v_countermeasure_id = 'D3-CH';
        SET v_confidence = 0.93;
    ELSEIF v_event_desc LIKE '%rdp%' OR v_event_desc LIKE '%remote%desktop%' THEN
        SET v_technique_id = 'T1021.001';
        SET v_countermeasure_id = 'D3-TF';
        SET v_confidence = 0.78;
    ELSEIF v_event_desc LIKE '%dns%tunnel%' THEN
        SET v_technique_id = 'T1071.004';
        SET v_countermeasure_id = 'D3-DNSTA';
        SET v_confidence = 0.89;
    ELSEIF v_event_desc LIKE '%ransomware%' OR v_event_desc LIKE '%encrypt%' THEN
        SET v_technique_id = 'T1486';
        SET v_countermeasure_id = 'D3-BDU';
        SET v_confidence = 0.95;
    ELSEIF v_event_desc LIKE '%powershell%' THEN
        SET v_technique_id = 'T1059.001';
        SET v_countermeasure_id = 'D3-PSA';
        SET v_confidence = 0.82;
    ELSE
        SET v_technique_id = 'T1059';
        SET v_countermeasure_id = 'D3-NTA';
        SET v_confidence = 0.60;
    END IF;
    
    -- Insert correlation
    INSERT INTO THREAT_CORRELATION (log_id, technique_id, countermeasure_id, confidence_score, correlated_by)
    VALUES (p_log_id, v_technique_id, v_countermeasure_id, v_confidence, p_user_id);
    
END //

DELIMITER ;

-- ================================================================
-- STORED PROCEDURE 2: GENERATE_ALERT
-- Generate alerts based on correlation
-- ================================================================
DELIMITER //

CREATE PROCEDURE GENERATE_ALERT(
    IN p_correlation_id INT,
    IN p_assigned_to INT
)
BEGIN
    DECLARE v_alert_type VARCHAR(50);
    DECLARE v_severity VARCHAR(20);
    DECLARE v_description TEXT;
    DECLARE v_technique_name VARCHAR(255);
    
    -- Get correlation details
    SELECT mat.technique_name, mat.severity, rl.event_description
    INTO v_technique_name, v_severity, v_description
    FROM THREAT_CORRELATION tc
    JOIN MITRE_ATTACK_TECHNIQUES mat ON tc.technique_id = mat.technique_id
    JOIN RAW_LOGS rl ON tc.log_id = rl.log_id
    WHERE tc.correlation_id = p_correlation_id;
    
    -- Determine alert type
    IF v_technique_name LIKE '%Brute%' THEN
        SET v_alert_type = 'Intrusion';
    ELSEIF v_technique_name LIKE '%Exfiltration%' THEN
        SET v_alert_type = 'Data Breach';
    ELSEIF v_technique_name LIKE '%Malware%' OR v_technique_name LIKE '%Scripting%' THEN
        SET v_alert_type = 'Malware';
    ELSEIF v_technique_name LIKE '%Denial%' THEN
        SET v_alert_type = 'DDoS';
    ELSEIF v_technique_name LIKE '%Privilege%' THEN
        SET v_alert_type = 'Privilege Escalation';
    ELSE
        SET v_alert_type = 'Reconnaissance';
    END IF;
    
    -- Insert alert
    INSERT INTO ALERTS (correlation_id, alert_type, severity, assigned_to, description)
    VALUES (p_correlation_id, v_alert_type, v_severity, p_assigned_to, 
            CONCAT('ALERT: ', v_technique_name, ' - ', v_description));
    
END //

DELIMITER ;

-- ================================================================
-- TRIGGER 1: AUDIT_CSV_UPLOAD
-- Log CSV uploads automatically
-- ================================================================
DELIMITER //

CREATE TRIGGER AUDIT_CSV_UPLOAD
AFTER INSERT ON RAW_LOGS
FOR EACH ROW
BEGIN
    INSERT INTO AUDIT_LOGS (user_id, action_type, action_details, ip_address, status)
    VALUES (NEW.uploaded_by, 'CSV_UPLOAD', 
            CONCAT('Log inserted: ID=', NEW.log_id, ', Source=', NEW.source_ip, ', Severity=', NEW.severity),
            NEW.source_ip, 'Success');
END //

DELIMITER ;

-- ================================================================
-- TRIGGER 2: AUDIT_ALERT_CREATION
-- Log alert creation automatically
-- ================================================================
DELIMITER //

CREATE TRIGGER AUDIT_ALERT_CREATION
AFTER INSERT ON ALERTS
FOR EACH ROW
BEGIN
    INSERT INTO AUDIT_LOGS (user_id, action_type, action_details, status)
    VALUES (NEW.assigned_to, 'ALERT_CREATION',
            CONCAT('Alert created: ID=', NEW.alert_id, ', Type=', NEW.alert_type, ', Severity=', NEW.severity),
            'Success');
END //

DELIMITER ;
