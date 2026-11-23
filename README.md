# Medical Records Storage System (Azure VM + Blob SSE + IP Security)
**Cloud Computing Laboratory — Assignment 15**  
**Submitted by:** Suhas & Sujan  
**Application Domain:** Healthcare  
**Cloud Storage Type:** Object Storage (Azure Blob Storage)  
**Security Model:** VM + Storage Encryption at Rest (AES-256-GCM) + Hospital IP Whitelist Subnet (`192.168.10.0/24`) + RBAC (Doctors, Nurses, Admin)

---

## 🏥 Project Overview
The **Medical Records Storage System** is a cloud-native healthcare application designed to securely manage, encrypt, and retrieve sensitive Protected Health Information (PHI) such as laboratory profiles, diagnostic echocardiograms, clinical notes, and radiology scans.

The application satisfies every requirement and deliverable outlined in **Assignment 15**:
1. **Cloud Compute (VM):** Hosted on Ubuntu Linux Cloud VM (Python 3 / Flask).
2. **Object Storage:** Azure Blob Storage container (`patient-medical-records`).
3. **Storage Encryption:** Authenticated AES-256-GCM encryption-at-rest with Key Vault management and SHA-256 tamper-evident integrity hashes.
4. **IP-Based Network Restrictions:** Strict Hospital Subnet enforcement (`192.168.10.0/24` allowed; external public IPs denied).
5. **Role-Based Access Control (RBAC):** Three distinct groups:
   - **Doctors Group (`dr_suhas` - Dr. Suhas Patil):** Full patient history access, encrypted report uploads, on-the-fly decryption, and diagnostic assessments.
   - **Nurses Group (`nurse_sujan` - Nurse Sujan Rao):** Patient intake/registration, routine lab report uploads, vital sign recording. Restrictive policy blocks mass report export/downloading.
   - **Admin Group (`admin` - Suhas & Sujan):** Subnet firewall management, Key Vault monitoring, and security audit log inspection.
6. **Automated Security Test Suite:** 6-point verification suite verifying IP blocking, RBAC, ciphertext-at-rest entropy, and data integrity.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Flask and Cryptography libraries (Pre-installed)

### 2. Run Database Seeding
To initialize the SQLite database and generate sample encrypted medical blobs:
```bash
python init_db.py
```

### 3. Start the Web Server (Public / LAN Mode)
```bash
python app.py
```
- **Local Browser:** [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **Local Network / Wi-Fi (Phone, Tablet, Laptop):** `http://172.20.3.86:5000`
- **Worldwide Public Internet Tunnel:**
  Double-click `public_tunnel.bat` or run:
  ```bash
  ssh -R 80:localhost:5000 nokey@localhost.run
  ```
  This creates an instant public HTTPS URL accessible from anywhere on the internet.

### 4. Run Automated Security Verification Suite
Run the automated test runner in terminal:
```bash
python test_security.py
```
Expected output:
```text
Ran 6 tests in 0.174s
OK
ALL SECURITY TESTS PASSED SUCCESSFULLY! (100% COMPLIANCE)
```

---

## 🔑 Pre-Configured Test Accounts

| Role | Username | Password | Permitted Network | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Doctor** | `dr_suhas` | `Doctor@123` | Hospital Subnet (`192.168.10.0/24`) | Full clinical records, decrypt & download reports, upload reports |
| **Nurse** | `nurse_sujan` | `Nurse@123` | Hospital Subnet (`192.168.10.0/24`) | Register patients, record vitals, upload routine labs (Download restricted) |
| **Admin** | `admin` | `Admin@123` | Management Console / VPN | Manage firewall rules, view audit trails, storage account config |

*Note: In the web interface, use the 1-click role switcher at the top right to toggle between roles instantly during grading.*

---

## 🛡️ Demonstrating IP Restrictions (Hospital vs External)
Per the assignment prompt:
> Hospital Network: `192.168.10.0/24`  
> Allowed: Doctors  
> Denied: External IPs (e.g., `203.0.113.88`)

1. **Hospital Intranet Mode:**
   - In the top bar, click **"Hospital IP"** (`192.168.10.45`).
   - Notice the green shield and "ALLOWED" status.
   - Click "Proof", "View", or "Download" on any report to see successful AES-256 decryption.
2. **External Public Internet Mode:**
   - In the top bar, click **"External IP"** (`203.0.113.88`).
   - An alert banner appears warning of unauthorized network connection.
   - Attempt to download or view a report: The application intercepts the request and rejects it with an **HTTP 403 Forbidden** security block.
   - Visit the **Audit Trail Logs** tab to see the blocked intrusion attempt recorded with client IP and timestamp.

---

## 📋 Deliverables Mapping (Assignment 15)

| Deliverable | Location in Application / Repository |
| :--- | :--- |
| **1. Cloud Architecture Diagram** | Tab: **Architecture & RBAC Matrix** (Interactive SVG diagram) |
| **2. Patient Registration** | Tab: **Patient Registry** (`/api/patients` POST modal) |
| **3. Report Upload** | Tab: **Azure Blob Reports** (`/api/patients/<id>/reports` with AES-256 encryption) |
| **4. Report Retrieval** | Tab: **Azure Blob Reports** (On-the-fly decryption & instant download) |
| **5. Role-Based Access Matrix** | Tab: **Architecture & RBAC Matrix** (Complete Doctor vs Nurse vs Admin table) |
| **6. IP Restriction Configuration** | Tab: **IP Security & Firewall** (CIDR rule table & live subnet tester) |
| **7. Encryption Evidence** | Click **"Proof"** button on any report to view raw hex dump, nonce, and hashes |
| **8. Security Testing Report** | Tab: **Automated Security Test Suite** (Live 6-point test runner) |
| **9. Final Project Report** | Tab: **Project Report & Deliverables** + `PROJECT_REPORT.md` (Printable format) |

---

## 🏗️ Solution Architecture Summary
```
[Doctor/Nurse Workstation]           [External Public User]
  (IP: 192.168.10.45)                  (IP: 203.0.113.88)
          │                                     │
          ▼                                     ▼
 ┌─────────────────────────────────────────────────────┐
 │       Hospital Security Group / IP Firewall         │
 │     Subnet Allowed: 192.168.10.0/24 (CIDR Match)    │
 │            External IPs: REJECT (403)               │
 └─────────────────────────┬───────────────────────────┘
                           │ (Traffic Passed)
                           ▼
 ┌─────────────────────────────────────────────────────┐
 │            Cloud Virtual Machine (Linux VM)         │
 │  • Flask REST API Service                           │
 │  • RBAC Controller (Doctors, Nurses, Admin)         │
 │  • AES-256-GCM AEAD Cryptographic Engine            │
 │  • Tamper-Evident Security Audit Logger             │
 └─────────────────────────┬───────────────────────────┘
                           │ (Encrypted Blobs)
                           ▼
 ┌─────────────────────────────────────────────────────┐
 │       Azure Blob Storage (Object Storage Tier)      │
 │  • Container: patient-medical-records               │
 │  • AES-256 Server-Side Encryption (SSE)             │
 │  • SHA-256 Cryptographic Checksums                  │
 └─────────────────────────────────────────────────────┘
```
