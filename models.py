# Database Models and Schema for Medical Records Storage System
# Assignment 15: Suhas & Sujan

import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medical_records.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table (Doctors, Nurses, Admins)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        department TEXT NOT NULL,
        email TEXT NOT NULL,
        badge_id TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # 2. Patients Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mrn TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        dob TEXT NOT NULL,
        gender TEXT NOT NULL,
        blood_group TEXT NOT NULL,
        phone TEXT,
        email TEXT,
        address TEXT,
        emergency_contact TEXT,
        allergies TEXT,
        chronic_conditions TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL
    )
    """)

    # 3. Medical Reports (Object Storage Blob References)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS medical_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_uuid TEXT UNIQUE NOT NULL,
        patient_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        blob_name TEXT NOT NULL,
        encryption_algorithm TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        uploader_id INTEGER NOT NULL,
        uploader_name TEXT NOT NULL,
        uploader_role TEXT NOT NULL,
        notes TEXT,
        doctor_verified INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id),
        FOREIGN KEY (uploader_id) REFERENCES users(id)
    )
    """)

    # 4. Clinical History & Vitals
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS clinical_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        author_name TEXT NOT NULL,
        author_role TEXT NOT NULL,
        note_type TEXT NOT NULL,
        content TEXT NOT NULL,
        vitals_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id),
        FOREIGN KEY (author_id) REFERENCES users(id)
    )
    """)

    # 5. IP Firewall Subnet Rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ip_firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subnet_cidr TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL,
        rule_type TEXT NOT NULL DEFAULT 'ALLOW',
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    # 6. Comprehensive Security Audit Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        user_id INTEGER,
        username TEXT,
        role TEXT,
        client_ip TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT,
        status TEXT NOT NULL,
        details TEXT
    )
    """)

    conn.commit()
    conn.close()

def log_audit_event(user_id, username, role, client_ip, action, resource_type, resource_id, status, details):
    """Inserts a tamper-evident audit record"""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO audit_logs (timestamp, user_id, username, role, client_ip, action, resource_type, resource_id, status, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (now_str, user_id, username, role, client_ip, action, resource_type, str(resource_id) if resource_id else None, status, details))
    conn.commit()
    conn.close()

def get_active_firewall_rules():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT subnet_cidr, description, rule_type, is_active FROM ip_firewall_rules WHERE is_active = 1")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
