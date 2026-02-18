-- ================================================================
-- ThreatOps SIEM Database Schema - PostgreSQL for Supabase
-- Converted from MySQL schema.sql
-- ================================================================

-- TABLE 1: USERS (Authentication & RBAC)
CREATE TABLE IF NOT EXISTS USERS (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('Admin', 'Analyst', 'Manager', 'Engineer', 'Responder', 'Hunter')),
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- TABLE 2: RAW_LOGS (Raw Security Event Data)
CREATE TABLE IF NOT EXISTS RAW_LOGS (
    log_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    protocol VARCHAR(20) NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP', 'RDP', 'SMB', 'WMI', 'RPC', 'LDAP')),
    port INTEGER CHECK (port IS NULL OR (port >= 1 AND port <= 65535)),
    event_description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    uploaded_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (uploaded_by) REFERENCES USERS(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON RAW_LOGS(timestamp);
CREATE INDEX IF NOT EXISTS idx_severity ON RAW_LOGS(severity);
CREATE INDEX IF NOT EXISTS idx_source_ip ON RAW_LOGS(source_ip);

-- TABLE 3: MITRE_ATTACK_TECHNIQUES (ATT&CK Framework)
CREATE TABLE IF NOT EXISTS MITRE_ATTACK_TECHNIQUES (
    technique_id VARCHAR(50) PRIMARY KEY,
    technique_name VARCHAR(255) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical'))
);

CREATE INDEX IF NOT EXISTS idx_tactic ON MITRE_ATTACK_TECHNIQUES(tactic);

-- TABLE 4: MITRE_DEFEND_COUNTERMEASURES (D3FEND Framework)
CREATE TABLE IF NOT EXISTS MITRE_DEFEND_COUNTERMEASURES (
    countermeasure_id VARCHAR(50) PRIMARY KEY,
    countermeasure_name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT,
    implementation_cost NUMERIC(10, 2) CHECK (implementation_cost >= 0),
    effectiveness_rating VARCHAR(20) NOT NULL CHECK (effectiveness_rating IN ('Low', 'Medium', 'High', 'Very High'))
);

-- TABLE 5: THREAT_CORRELATION (Links Logs to MITRE Frameworks)
CREATE TABLE IF NOT EXISTS THREAT_CORRELATION (
    correlation_id SERIAL PRIMARY KEY,
    log_id INTEGER NOT NULL,
    technique_id VARCHAR(50) NOT NULL,
    countermeasure_id VARCHAR(50),
    confidence_score NUMERIC(3, 2) CHECK (confidence_score BETWEEN 0 AND 1),
    correlated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    correlated_by INTEGER,
    FOREIGN KEY (log_id) REFERENCES RAW_LOGS(log_id) ON DELETE CASCADE,
    FOREIGN KEY (technique_id) REFERENCES MITRE_ATTACK_TECHNIQUES(technique_id),
    FOREIGN KEY (countermeasure_id) REFERENCES MITRE_DEFEND_COUNTERMEASURES(countermeasure_id),
    FOREIGN KEY (correlated_by) REFERENCES USERS(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_log_id ON THREAT_CORRELATION(log_id);
CREATE INDEX IF NOT EXISTS idx_technique ON THREAT_CORRELATION(technique_id);

-- TABLE 6: ALERTS (Generated Threat Alerts)
CREATE TABLE IF NOT EXISTS ALERTS (
    alert_id SERIAL PRIMARY KEY,
    correlation_id INTEGER NOT NULL,
    alert_type VARCHAR(50) NOT NULL CHECK (alert_type IN ('Intrusion', 'Data Breach', 'Malware', 'DDoS', 'Privilege Escalation', 'Reconnaissance')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status VARCHAR(20) DEFAULT 'Open' CHECK (status IN ('Open', 'In Progress', 'Resolved', 'False Positive')),
    assigned_to INTEGER,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (correlation_id) REFERENCES THREAT_CORRELATION(correlation_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to) REFERENCES USERS(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_status ON ALERTS(status);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON ALERTS(severity);
CREATE INDEX IF NOT EXISTS idx_created ON ALERTS(created_at);

-- TABLE 7: AUDIT_LOGS (System Audit Trail)
CREATE TABLE IF NOT EXISTS AUDIT_LOGS (
    audit_id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN ('LOGIN', 'LOGOUT', 'QUERY_EXECUTION', 'CSV_UPLOAD', 'ALERT_CREATION', 'USER_MANAGEMENT', 'DATA_MODIFICATION')),
    action_details TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'Success' CHECK (status IN ('Success', 'Failure')),
    FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_user ON AUDIT_LOGS(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON AUDIT_LOGS(timestamp);
CREATE INDEX IF NOT EXISTS idx_action ON AUDIT_LOGS(action_type);

-- ================================================================
-- INSERT SOC/CIRT TEAM USERS
-- Using encode(digest()) for SHA256 hashing in PostgreSQL
-- ================================================================
INSERT INTO USERS (username, password_hash, role, email, created_at, last_login, is_active) VALUES
('rajesh_kumar', encode(digest('ADM123', 'sha256'), 'hex'), 'Admin', 'rajesh.kumar@threatops.local', '2026-01-01 08:00:00', '2026-02-15 09:30:00', TRUE),
('deepak_verma', encode(digest('ADM123', 'sha256'), 'hex'), 'Admin', 'deepak.verma@threatops.local', '2026-01-02 09:00:00', '2026-02-14 18:00:00', TRUE),
('priya_sharma', encode(digest('MGR123', 'sha256'), 'hex'), 'Manager', 'priya.sharma@threatops.local', '2026-01-01 08:15:00', '2026-02-15 10:00:00', TRUE),
('amit_patel', encode(digest('ANLST123', 'sha256'), 'hex'), 'Analyst', 'amit.patel@threatops.local', '2026-01-05 10:00:00', '2026-02-14 16:20:00', TRUE),
('sneha_singh', encode(digest('ANLST123', 'sha256'), 'hex'), 'Analyst', 'sneha.singh@threatops.local', '2026-01-10 11:30:00', '2026-02-15 07:15:00', TRUE),
('rohan_gupta', encode(digest('ANLST123', 'sha256'), 'hex'), 'Analyst', 'rohan.gupta@threatops.local', '2026-01-15 14:00:00', '2026-02-13 10:30:00', TRUE),
('meera_krishnan', encode(digest('ANLST123', 'sha256'), 'hex'), 'Analyst', 'meera.krishnan@threatops.local', '2026-01-18 09:30:00', '2026-02-12 14:45:00', TRUE),
('arjun_reddy', encode(digest('ENG123', 'sha256'), 'hex'), 'Engineer', 'arjun.reddy@threatops.local', '2026-01-08 08:30:00', '2026-02-14 15:00:00', TRUE),
('vikram_desai', encode(digest('ENG123', 'sha256'), 'hex'), 'Engineer', 'vikram.desai@threatops.local', '2026-01-12 13:00:00', '2026-02-13 11:30:00', TRUE),
('kavya_iyer', encode(digest('RESP123', 'sha256'), 'hex'), 'Responder', 'kavya.iyer@threatops.local', '2026-01-06 16:00:00', '2026-02-15 08:45:00', TRUE),
('sanjay_rao', encode(digest('RESP123', 'sha256'), 'hex'), 'Responder', 'sanjay.rao@threatops.local', '2026-01-14 10:30:00', '2026-02-11 16:20:00', TRUE),
('ananya_nair', encode(digest('HUNT123', 'sha256'), 'hex'), 'Hunter', 'ananya.nair@threatops.local', '2026-01-10 15:00:00', '2026-02-14 12:00:00', TRUE),
('inactive_user', encode(digest('ANLST123', 'sha256'), 'hex'), 'Analyst', 'inactive@threatops.local', '2026-01-01 08:00:00', '2026-01-05 10:00:00', FALSE);

-- POPULATE MITRE ATT&CK TECHNIQUES
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

-- POPULATE MITRE D3FEND COUNTERMEASURES
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

-- POPULATE RAW_LOGS (Sample Security Event Data)
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

-- POPULATE THREAT_CORRELATION
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

-- POPULATE ALERTS
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

-- POPULATE AUDIT_LOGS
INSERT INTO AUDIT_LOGS (user_id, action_type, action_details, ip_address, timestamp, status) VALUES
(1, 'LOGIN', 'Admin user logged in successfully', '192.168.1.10', '2026-02-14 08:00:00', 'Success'),
(2, 'LOGIN', 'Analyst user logged in successfully', '192.168.1.15', '2026-02-14 08:05:00', 'Success'),
(1, 'QUERY_EXECUTION', 'Executed query: SELECT * FROM THREAT_INTELLIGENCE_DASHBOARD', '192.168.1.10', '2026-02-14 08:30:00', 'Success'),
(2, 'CSV_UPLOAD', 'Uploaded CSV file with 10 security logs', '192.168.1.15', '2026-02-14 09:00:00', 'Success'),
(1, 'USER_MANAGEMENT', 'Created new analyst user: john_doe', '192.168.1.10', '2026-02-14 09:30:00', 'Success');

-- ================================================================
-- VIEW 1: THREAT_INTELLIGENCE_DASHBOARD
-- ================================================================
CREATE OR REPLACE VIEW THREAT_INTELLIGENCE_DASHBOARD AS
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

-- VIEW 2: USER_ACTIVITY_SUMMARY
CREATE OR REPLACE VIEW USER_ACTIVITY_SUMMARY AS
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
-- FUNCTION 1: CORRELATE_THREAT
-- Automatically correlate raw logs with MITRE techniques
-- ================================================================
CREATE OR REPLACE FUNCTION CORRELATE_THREAT(
    p_log_id INTEGER,
    p_user_id INTEGER
) RETURNS VOID AS $$
DECLARE
    v_technique_id VARCHAR(50);
    v_countermeasure_id VARCHAR(50);
    v_confidence NUMERIC(3,2);
    v_event_desc TEXT;
    v_severity VARCHAR(20);
BEGIN
    SELECT event_description, severity INTO v_event_desc, v_severity
    FROM RAW_LOGS WHERE log_id = p_log_id;
    
    v_confidence := 0.75;
    
    IF v_event_desc ILIKE '%brute%force%' OR v_event_desc ILIKE '%failed%login%' THEN
        v_technique_id := 'T1110';
        v_countermeasure_id := 'D3-AL';
        v_confidence := 0.85;
    ELSIF v_event_desc ILIKE '%port%scan%' OR v_event_desc ILIKE '%nmap%' THEN
        v_technique_id := 'T1046';
        v_countermeasure_id := 'D3-NTA';
        v_confidence := 0.80;
    ELSIF v_event_desc ILIKE '%dos%' OR v_event_desc ILIKE '%flood%' THEN
        v_technique_id := 'T1499';
        v_countermeasure_id := 'D3-RTF';
        v_confidence := 0.90;
    ELSIF v_event_desc ILIKE '%malware%' OR v_event_desc ILIKE '%trojan%' THEN
        v_technique_id := 'T1059';
        v_countermeasure_id := 'D3-EXP';
        v_confidence := 0.88;
    ELSIF v_event_desc ILIKE '%phishing%' OR v_event_desc ILIKE '%spear%' THEN
        v_technique_id := 'T1566';
        v_countermeasure_id := 'D3-EAL';
        v_confidence := 0.92;
    ELSIF v_event_desc ILIKE '%exfiltration%' OR v_event_desc ILIKE '%data%transfer%' THEN
        v_technique_id := 'T1048';
        v_countermeasure_id := 'D3-DLP';
        v_confidence := 0.87;
    ELSIF v_event_desc ILIKE '%privilege%escalation%' OR v_event_desc ILIKE '%exploit%' THEN
        v_technique_id := 'T1068';
        v_countermeasure_id := 'D3-PAM';
        v_confidence := 0.91;
    ELSIF v_event_desc ILIKE '%credential%dump%' OR v_event_desc ILIKE '%mimikatz%' THEN
        v_technique_id := 'T1003';
        v_countermeasure_id := 'D3-CH';
        v_confidence := 0.93;
    ELSIF v_event_desc ILIKE '%rdp%' OR v_event_desc ILIKE '%remote%desktop%' THEN
        v_technique_id := 'T1021.001';
        v_countermeasure_id := 'D3-TF';
        v_confidence := 0.78;
    ELSIF v_event_desc ILIKE '%dns%tunnel%' THEN
        v_technique_id := 'T1071.004';
        v_countermeasure_id := 'D3-DNSTA';
        v_confidence := 0.89;
    ELSIF v_event_desc ILIKE '%ransomware%' OR v_event_desc ILIKE '%encrypt%' THEN
        v_technique_id := 'T1486';
        v_countermeasure_id := 'D3-BDU';
        v_confidence := 0.95;
    ELSIF v_event_desc ILIKE '%powershell%' THEN
        v_technique_id := 'T1059.001';
        v_countermeasure_id := 'D3-PSA';
        v_confidence := 0.82;
    ELSE
        v_technique_id := 'T1059';
        v_countermeasure_id := 'D3-NTA';
        v_confidence := 0.60;
    END IF;
    
    INSERT INTO THREAT_CORRELATION (log_id, technique_id, countermeasure_id, confidence_score, correlated_by)
    VALUES (p_log_id, v_technique_id, v_countermeasure_id, v_confidence, p_user_id);
    
END;
$$ LANGUAGE plpgsql;

-- FUNCTION 2: GENERATE_ALERT
CREATE OR REPLACE FUNCTION GENERATE_ALERT(
    p_correlation_id INTEGER,
    p_assigned_to INTEGER
) RETURNS VOID AS $$
DECLARE
    v_alert_type VARCHAR(50);
    v_severity VARCHAR(20);
    v_description TEXT;
    v_technique_name VARCHAR(255);
BEGIN
    SELECT mat.technique_name, mat.severity, rl.event_description
    INTO v_technique_name, v_severity, v_description
    FROM THREAT_CORRELATION tc
    JOIN MITRE_ATTACK_TECHNIQUES mat ON tc.technique_id = mat.technique_id
    JOIN RAW_LOGS rl ON tc.log_id = rl.log_id
    WHERE tc.correlation_id = p_correlation_id;
    
    IF v_technique_name ILIKE '%Brute%' THEN
        v_alert_type := 'Intrusion';
    ELSIF v_technique_name ILIKE '%Exfiltration%' THEN
        v_alert_type := 'Data Breach';
    ELSIF v_technique_name ILIKE '%Malware%' OR v_technique_name ILIKE '%Scripting%' THEN
        v_alert_type := 'Malware';
    ELSIF v_technique_name ILIKE '%Denial%' THEN
        v_alert_type := 'DDoS';
    ELSIF v_technique_name ILIKE '%Privilege%' THEN
        v_alert_type := 'Privilege Escalation';
    ELSE
        v_alert_type := 'Reconnaissance';
    END IF;
    
    INSERT INTO ALERTS (correlation_id, alert_type, severity, assigned_to, description)
    VALUES (p_correlation_id, v_alert_type, v_severity, p_assigned_to, 
            CONCAT('ALERT: ', v_technique_name, ' - ', v_description));
    
END;
$$ LANGUAGE plpgsql;

-- TRIGGER 1: AUDIT_CSV_UPLOAD
CREATE OR REPLACE FUNCTION audit_csv_upload_func() 
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO AUDIT_LOGS (user_id, action_type, action_details, ip_address, status)
    VALUES (NEW.uploaded_by, 'CSV_UPLOAD', 
            CONCAT('Log inserted: ID=', NEW.log_id, ', Source=', NEW.source_ip, ', Severity=', NEW.severity),
            NEW.source_ip, 'Success');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_csv_upload
AFTER INSERT ON RAW_LOGS
FOR EACH ROW
EXECUTE FUNCTION audit_csv_upload_func();

-- TRIGGER 2: AUDIT_ALERT_CREATION
CREATE OR REPLACE FUNCTION audit_alert_creation_func() 
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO AUDIT_LOGS (user_id, action_type, action_details, status)
    VALUES (NEW.assigned_to, 'ALERT_CREATION',
            CONCAT('Alert created: ID=', NEW.alert_id, ', Type=', NEW.alert_type, ', Severity=', NEW.severity),
            'Success');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_alert_creation
AFTER INSERT ON ALERTS
FOR EACH ROW
EXECUTE FUNCTION audit_alert_creation_func();
