# PROJECT REPORT: CLOUD-HOSTED MEDICAL RECORDS STORAGE SYSTEM
### Course: Cloud Computing & Distributed Storage Systems Laboratory
### Assignment: 15 (Healthcare Domain)
### Authors: Suhas & Sujan
### Date of Submission: November 2026

---

## 1. EXECUTIVE SUMMARY & OBJECTIVES
The management of electronic healthcare records necessitates stringent data confidentiality, high availability, regulatory compliance (e.g., HIPAA, GDPR, ISO 27799), and scalable storage economics. In traditional on-premise infrastructure, healthcare institutions suffer from capacity exhaustion, elevated hardware procurement costs, and vulnerability to localized physical disasters.

This project implements a secure, cloud-hosted **Medical Records Storage System** designed and engineered by **Suhas & Sujan** for **Assignment 15**. The application decouples elastic compute processing hosted on a **Linux Cloud Virtual Machine (VM)** from highly durable, scalable object storage hosted on **Azure Blob Storage**.

### Primary System Objectives:
1. **Cloud Compute Provisioning:** Deploy a robust web application server on a cloud VM (Ubuntu Linux).
2. **Object Storage Integration:** Utilize Azure Blob Storage container (`patient-medical-records`) for storing patient medical reports, diagnostic imaging, and laboratory sheets.
3. **Storage Encryption-at-Rest:** Implement AES-256-GCM authenticated server-side encryption (SSE) so all sensitive medical records committed to the storage layer are encrypted with zero plaintext leakage.
4. **IP-Based Network Restrictions:** Enforce network security policies restricting clinical report access exclusively to the authorized **Hospital Subnet (`192.168.10.0/24`)**, rejecting external public IP traffic with an HTTP 403 Forbidden status.
5. **Role-Based Access Control (RBAC):** Define and enforce three granular security groups:
   - **Doctors Group:** Full clinical management, report upload, report decryption, and diagnostic notes.
   - **Nurses Group:** Patient intake/registration, routine vital signs recording, lab upload (mass file download restricted).
   - **Admin Group:** Cloud storage configuration, firewall subnet rules management, and immutable audit inspection.
6. **Auditability & Integrity:** Generate SHA-256 cryptographic hashes for every ingested file and log all security events to an immutable audit ledger.

---

## 2. CLOUD INFRASTRUCTURE & ARCHITECTURE SPECIFICATION

### 2.1 Cloud Resource Allocation
| Resource Component | Cloud Provider / Specification | Purpose |
| :--- | :--- | :--- |
| **Compute Engine (VM)** | Ubuntu 24.04 LTS (Azure Virtual Machine / AWS EC2) | Web application server, REST APIs, session management |
| **Object Storage** | Azure Blob Storage (`patient-medical-records`) | Encrypted storage of patient files, scans, and reports |
| **Cryptographic Engine** | AES-256-GCM AEAD (Azure Key Vault Managed) | Symmetric authenticated file encryption before disk commit |
| **Database Tier** | SQLite / Azure SQL Engine | Relational metadata, user directories, patient MRN index |
| **Firewall / NSG** | Network Security Group (CIDR Subnet Whitelist) | Restricting clinical access to Hospital Subnet (`192.168.10.0/24`) |

### 2.2 Architectural Topology
```
 [Hospital Intranet: 192.168.10.0/24]               [External Untrusted WAN]
 (Doctor Workstation / Nurse Station)             (Home Internet / Public IP)
                  │                                            │
                  ▼                                            ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │         Network Security Group / Subnet Inspection Firewall           │
   │  • Evaluates Client IP against CIDR: 192.168.10.0/24                  │
   │  • Action if Hospital Subnet: PASS                                    │
   │  • Action if External IP: DROP / 403 Forbidden                        │
   └───────────────────────────────────┬───────────────────────────────────┘
                                       │ (Allowed Traffic)
                                       ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │             Cloud Virtual Machine (Linux Ubuntu VM)                   │
   │  • Application Server: Python 3 Flask REST Services                   │
   │  • RBAC Controller: Doctors / Nurses / Admin                          │
   │  • Cryptographic Engine: AES-256-GCM AEAD with 12-byte Nonce          │
   │  • Integrity Validator: SHA-256 Checksum Engine                       │
   │  • Security Audit Logger: Tamper-Evident Chronological Ledger         │
   └───────────────────────────────────┬───────────────────────────────────┘
                                       │ (Encrypted Binary Blobs)
                                       ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │             Azure Blob Storage (Cloud Object Storage Tier)            │
   │  • Container: "patient-medical-records"                               │
   │  • Server-Side Encryption (SSE) Enabled (AES-256)                     │
   │  • Hot Access Tier for Immediate Clinical Retrieval                   │
   │  • SHA-256 Content-MD5 / Digest Integrity Metadata                   │
   └───────────────────────────────────────────────────────────────────────┘
```

---

## 3. SECURITY IMPLEMENTATION & ROLE PRIVILEGE SEPARATION

### 3.1 Role-Based Access Control (RBAC) Matrix
The application implements strict principle of least privilege:

| Operation / Feature | Doctors (`dr_suhas`) | Nurses (`nurse_sujan`) | Administrator (`admin`) |
| :--- | :---: | :---: | :---: |
| **View Patient Demographic Profile** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED |
| **Register New Patient Records** | ✅ ALLOWED | ✅ ALLOWED | ✅ ALLOWED |
| **Upload Diagnostic Reports / Labs** | ✅ ALLOWED | ✅ ALLOWED (Labs) | ✅ ALLOWED |
| **Decrypt & Download Full Reports** | ✅ ALLOWED | ❌ RESTRICTED | ✅ ALLOWED |
| **Hospital IP Requirement (192.168.10.0/24)** | 🔒 ENFORCED | 🔒 ENFORCED | 🛡️ VPN / Console |
| **Record Clinical Diagnoses** | ✅ ALLOWED | ❌ RESTRICTED | ➖ Segregated |
| **Record Triage & Vital Signs** | ✅ ALLOWED | ✅ ALLOWED | ➖ Segregated |
| **Modify Subnet Whitelist / Firewall** | ❌ RESTRICTED | ❌ RESTRICTED | ✅ FULL ACCESS |
| **Inspect System Security Audit Logs** | ✅ View Only | ❌ RESTRICTED | ✅ FULL ACCESS |

### 3.2 IP-Based Subnet Whitelist (Hospital Intranet vs External)
In conformance with Assignment 15 specifications:
```
Hospital Network: 192.168.10.0/24
Allowed: Doctors, Nurses
Denied: External IPs (e.g. 203.0.113.88)
```
- **CIDR Algorithm:** The system utilizes `ipaddress.ip_network` to parse client addresses extracted from socket remote addresses or reverse-proxy headers (`X-Forwarded-For`).
- **Enforcement Point:** When any user attempts to view, upload, or download medical report blobs, the security filter validates the client IP. If the address falls outside `192.168.10.0/24`, the request is immediately aborted with HTTP 403, and an intrusion event is recorded in the immutable audit table.

### 3.3 Storage Encryption-at-Rest (AES-256-GCM)
Every file uploaded is encrypted using Authenticated Encryption with Associated Data (AEAD):
- **Algorithm:** AES-256-GCM (Galois/Counter Mode).
- **Key Provider:** Azure Key Vault simulation with a 256-bit cryptographic master key.
- **Nonce/IV:** Unique 12-byte random cryptographically secure initialization vector generated per blob (`os.urandom(12)`).
- **Integrity Tag:** 16-byte authentication tag generated to prevent ciphertext tampering.
- **Data Integrity:** A pre-encryption SHA-256 checksum is stored in the database metadata. Upon retrieval, the payload is decrypted, re-hashed, and compared against the recorded digest.

---

## 4. DATABASE & OBJECT STORAGE SCHEMA

### 4.1 Relational Metadata Schema (SQLite / Azure SQL)
1. **`users` Table:**
   - `id` (INTEGER PRIMARY KEY)
   - `username` (VARCHAR 64, UNIQUE)
   - `password_hash` (VARCHAR 64, SHA-256 + Salt)
   - `full_name` (VARCHAR 128)
   - `role` (VARCHAR 32: `ADMIN`, `DOCTOR`, `NURSE`)
   - `department` (VARCHAR 128)
   - `email` (VARCHAR 128)
   - `badge_id` (VARCHAR 32)
2. **`patients` Table:**
   - `id` (INTEGER PRIMARY KEY)
   - `mrn` (VARCHAR 32, UNIQUE, e.g., `MRN-2026-0811`)
   - `full_name` (VARCHAR 128)
   - `dob` (DATE)
   - `gender` (VARCHAR 16)
   - `blood_group` (VARCHAR 8)
   - `phone`, `email`, `address`, `emergency_contact`
   - `allergies` (TEXT)
   - `chronic_conditions` (TEXT)
3. **`medical_reports` Table:**
   - `id` (INTEGER PRIMARY KEY)
   - `report_uuid` (VARCHAR 64, UNIQUE)
   - `patient_id` (FOREIGN KEY -> `patients.id`)
   - `title`, `category`, `file_name`, `file_size`, `mime_type`
   - `blob_name` (VARCHAR 128, pointer to Azure Blob Storage)
   - `encryption_algorithm` (`AES-256-GCM`)
   - `sha256_hash` (Pre-encryption digest)
   - `uploader_id`, `uploader_name`, `uploader_role`
   - `doctor_verified` (BOOLEAN)
4. **`audit_logs` Table:**
   - `id` (INTEGER PRIMARY KEY)
   - `timestamp` (ISO 8601 UTC)
   - `user_id`, `username`, `role`
   - `client_ip`
   - `action`, `resource_type`, `resource_id`, `status`, `details`

---

## 5. AUTOMATED SECURITY TESTING & VERIFICATION REPORT

To validate all requirements of Assignment 15, an automated test harness (`test_security.py`) was developed and executed.

### Test Execution Summary
```text
=================================================================
RUNNING SECURITY TEST SUITE (ASSIGNMENT 15 - SUHAS & SUJAN)
=================================================================
test_01_doctor_access_hospital_ip_allowed ... ok
test_02_external_ip_access_blocked ... ok
test_03_nurse_rbac_download_restricted ... ok
test_04_storage_encryption_at_rest ... ok
test_05_data_integrity_sha256_match ... ok
test_06_audit_logging_active ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.174s

OK - ALL SECURITY TESTS PASSED SUCCESSFULLY! (100% COMPLIANCE)
```

### Detailed Verification Breakdown:
1. **`SEC-TEST-01` (Doctor in Hospital Subnet):**  
   - *Input:* IP `192.168.10.45`, Role: Doctor.  
   - *Result:* **ALLOWED (HTTP 200 OK)**. Decrypted clinical data served.
2. **`SEC-TEST-02` (External Untrusted IP Interception):**  
   - *Input:* IP `203.0.113.88`, Role: Doctor.  
   - *Result:* **BLOCKED (HTTP 403 Forbidden)**. Firewall drops request; audit entry created.
3. **`SEC-TEST-03` (RBAC Privilege Segregation):**  
   - *Input:* Role: Nurse attempting report mass download.  
   - *Result:* **DENIED (HTTP 403 RBAC Violation)**. File export reserved for Doctors/Admins.
4. **`SEC-TEST-04` (Storage Encryption Verification):**  
   - *Verification:* Direct disk inspection of Azure blob container files shows high-entropy ciphertext with zero plaintext strings (`AES-256-GCM`).
5. **`SEC-TEST-05` (Cryptographic Data Integrity):**  
   - *Verification:* Decrypted payload re-hashed; computed SHA-256 digest matches pre-upload digest byte-for-byte.
6. **`SEC-TEST-06` (Immutable Security Audit Logging):**  
   - *Verification:* Every authorization event, IP block, and file download is permanently recorded in the audit trail.

---

## 6. PROJECT DEMONSTRATION WALKTHROUGH FOR EVALUATORS

1. **Patient Registry & Intake:**
   - Navigate to the **Patient Registry** tab.
   - Click **"Register Patient"** to record demographic details, blood group, allergies, and chronic conditions. The system assigns a unique Medical Record Number (MRN).
2. **Uploading an Encrypted Report:**
   - In the **Azure Blob Reports** tab, click **"Upload & Encrypt Medical Report"**.
   - Attach a laboratory file or enter clinical text.
   - Observe real-time SHA-256 hashing and AES-256-GCM encryption before writing to the container.
3. **Demonstrating Storage Encryption Proof:**
   - Click the green **"Proof"** button next to any report.
   - View the cryptographic proof modal displaying the initialization vector (nonce), plaintext vs ciphertext sizes, SHA-256 digest, raw hex dump of the encrypted blob, and simulated Azure SAS token.
4. **Testing IP Restrictions (The Hospital vs External Test):**
   - Click **"Hospital IP"** (`192.168.10.45`): View and download reports without restriction.
   - Click **"External IP"** (`203.0.113.88`): The top security banner turns red. Attempt to download or view a report; observe immediate **403 Forbidden** rejection!
   - Switch to the **Audit Trail Logs** tab to show the recorded intrusion attempt.
5. **Role-Based Access Control Switcher:**
   - Switch the active profile dropdown to **Nurse Sujan Rao**. Attempting to download confidential reports is denied by role-based policy.

---

## 7. CONCLUSION
This project successfully fulfills all deliverables specified for **Assignment 15: Medical Records Storage System** in the Cloud Computing Laboratory curriculum. By combining cloud virtual machines with Azure Blob object storage, rigorous AES-256 encryption-at-rest, and hospital intranet IP subnet restrictions, the system establishes a secure, compliant, and production-ready architectural foundation for enterprise healthcare records.
