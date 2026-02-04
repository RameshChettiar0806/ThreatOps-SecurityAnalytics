CREATE DATABASE IF NOT EXISTS threatops;
USE threatops;

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(100) NOT NULL,
    destination_ip VARCHAR(100) NOT NULL,
    protocol VARCHAR(50) NOT NULL,
    event_description TEXT NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    mitre_attack_id VARCHAR(50) NOT NULL,
    mitre_attack_name VARCHAR(255) NOT NULL,
    mitre_d3fend_technique VARCHAR(255) NOT NULL
);
