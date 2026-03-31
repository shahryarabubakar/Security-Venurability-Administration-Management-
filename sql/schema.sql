-- =============================================
-- SVAMS v3 - Vulnerability Management System
-- Complete Schema with Scans Support
-- =============================================

CREATE DATABASE IF NOT EXISTS svams;
USE svams;

-- Drop tables in correct order (children first)
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS remediation_notes;
DROP TABLE IF EXISTS asset_tags;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS users;

-- =============================================
-- Users Table
-- =============================================
CREATE TABLE users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    email         VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('admin','analyst') NOT NULL DEFAULT 'analyst',
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP NULL
);

-- =============================================
-- Assets Table
-- =============================================
CREATE TABLE assets (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    owner_id         INT,
    asset_name       VARCHAR(100) NOT NULL,
    ip_address       VARCHAR(50)  NOT NULL UNIQUE,
    operating_system VARCHAR(100),
    asset_type       VARCHAR(50)  DEFAULT 'Server',
    status           ENUM('Active','Inactive','Retired') DEFAULT 'Active',
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_ip (ip_address)
);

-- =============================================
-- Scans Table (NEW - for scan history)
-- =============================================
CREATE TABLE scans (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    scan_name     VARCHAR(100) NOT NULL,
    scanner_type  ENUM('ZAP','Nessus','Nmap','Manual') NOT NULL DEFAULT 'ZAP',
    started_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at  TIMESTAMP NULL,
    status        ENUM('Running','Completed','Failed') DEFAULT 'Completed',
    user_id       INT,
    notes         TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- =============================================
-- Vulnerabilities Table (Enhanced)
-- =============================================
CREATE TABLE vulnerabilities (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    asset_id        INT NOT NULL,
    scan_id         INT NULL,
    cve_id          VARCHAR(50) NULL,
    vuln_name       VARCHAR(255) NOT NULL,
    risk_level      ENUM('Critical','High','Medium','Low','Info') NOT NULL DEFAULT 'Low',
    cvss_score      DECIMAL(3,1) NULL,
    description     TEXT,
    solution        TEXT,
    proof           TEXT,
    status          ENUM('Open','In Progress','Resolved','False Positive') DEFAULT 'Open',
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at     TIMESTAMP NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id)  REFERENCES scans(id) ON DELETE SET NULL,
    INDEX idx_asset_status (asset_id, status),
    INDEX idx_risk (risk_level)
);

-- =============================================
-- Tags Table
-- =============================================
CREATE TABLE tags (
    id    INT AUTO_INCREMENT PRIMARY KEY,
    name  VARCHAR(50) NOT NULL UNIQUE,
    color VARCHAR(7)  NOT NULL DEFAULT '#4f8ef7'
);

-- =============================================
-- Asset Tags (Many-to-Many)
-- =============================================
CREATE TABLE asset_tags (
    asset_id INT NOT NULL,
    tag_id   INT NOT NULL,
    PRIMARY KEY (asset_id, tag_id),
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id)   REFERENCES tags(id)   ON DELETE CASCADE
);

-- =============================================
-- Remediation Notes
-- =============================================
CREATE TABLE remediation_notes (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    vuln_id    INT NOT NULL,
    user_id    INT,
    note       TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- =============================================
-- Audit Log
-- =============================================
CREATE TABLE audit_log (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT,
    action       VARCHAR(50)  NOT NULL,
    target_type  VARCHAR(50)  NOT NULL,
    target_id    INT,
    detail       TEXT,
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- =============================================
-- Sample Data
-- =============================================

-- Users
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@svams.local', 'pbkdf2:sha256:600000$placeholder_admin', 'admin'),
('analyst1', 'analyst1@svams.local', 'pbkdf2:sha256:600000$placeholder_analyst', 'analyst');

-- Tags
INSERT INTO tags (name, color) VALUES
('production', '#e0464b'),
('staging', '#f0b429'),
('internal', '#4f8ef7'),
('critical', '#e0464b'),
('dmz', '#f07320'),
('patched', '#2dbd6e');

-- Scans
INSERT INTO scans (scan_name, scanner_type, status, notes) VALUES
('ZAP Baseline Scan - Web Server', 'ZAP', 'Completed', 'Initial scan imported from OWASP ZAP'),
('Manual Vulnerability Entry', 'Manual', 'Completed', 'Added manually by admin');

-- Assets
INSERT INTO assets (owner_id, asset_name, ip_address, operating_system, asset_type, status) VALUES
(1, 'Web Server 01', '192.168.1.10', 'Ubuntu 22.04 LTS', 'Server', 'Active'),
(1, 'Database Server', '192.168.1.20', 'CentOS 8', 'Database', 'Active'),
(2, 'Dev Workstation', '192.168.1.50', 'Windows 11', 'Workstation', 'Active');

-- Asset Tags
INSERT INTO asset_tags (asset_id, tag_id) VALUES
(1, 1), (1, 4),   -- Web Server: production + critical
(2, 1), (2, 3),   -- DB Server: production + internal
(3, 2);           -- Dev: staging

-- Vulnerabilities
INSERT INTO vulnerabilities (asset_id, scan_id, vuln_name, risk_level, description, solution, status) VALUES
(1, 1, 'SQL Injection in Login Form', 'High', 'Unsanitized user input allows SQL injection.', 'Use prepared statements and input validation.', 'Open'),
(1, 1, 'Outdated OpenSSL Library', 'Critical', 'OpenSSL version vulnerable to multiple CVEs.', 'Upgrade to latest OpenSSL 3.x version.', 'In Progress'),
(2, 1, 'Weak Database Password Policy', 'High', 'Root account uses weak password.', 'Enforce strong password policy and rotate credentials.', 'Open'),
(3, 2, 'Missing Antivirus on Workstation', 'Medium', 'No active endpoint protection detected.', 'Install and update enterprise antivirus solution.', 'Open');

-- Remediation Notes
INSERT INTO remediation_notes (vuln_id, user_id, note) VALUES
(1, 1, 'Assigned to development team. Ticket #SEC-204 created.'),
(2, 1, 'Upgrade scheduled for next maintenance window.');

-- Audit Log Sample
INSERT INTO audit_log (user_id, action, target_type, target_id, detail) VALUES
(1, 'CREATE', 'asset', 1, 'Added Web Server 01'),
(1, 'IMPORT', 'vulnerability', 1, 'Imported from ZAP scan');
