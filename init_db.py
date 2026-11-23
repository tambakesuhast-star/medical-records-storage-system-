# Seed and Initialize Database & Object Storage with Realistic Healthcare Data
# Assignment 15: Suhas & Sujan - Medical Records Storage System

import os
import json
import uuid
from datetime import datetime, timezone, timedelta
from models import init_tables, get_db_connection, log_audit_event
from security import hash_password, ROLE_ADMIN, ROLE_DOCTOR, ROLE_NURSE
from storage_engine import AzureBlobStorageEngine

def seed_database():
    init_tables()
    conn = get_db_connection()
    cursor = conn.cursor()

    # Clear existing if needed
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM patients")
    cursor.execute("DELETE FROM medical_reports")
    cursor.execute("DELETE FROM clinical_notes")
    cursor.execute("DELETE FROM ip_firewall_rules")
    cursor.execute("DELETE FROM audit_logs")
    try:
        cursor.execute("DELETE FROM sqlite_sequence")
    except Exception:
        pass

    # 1. Seed Users (Admin, Doctor Suhas, Nurse Sujan)
    now = datetime.now(timezone.utc).isoformat()
    users_data = [
        ("admin", hash_password("Admin@123"), "Administrator Suhas & Sujan", ROLE_ADMIN, "Cloud & SecOps", "admin@hospital.azure.org", "ADM-001"),
        ("dr_suhas", hash_password("Doctor@123"), "Dr. Suhas Patil, MD", ROLE_DOCTOR, "Cardiovascular Medicine", "dr.suhas@hospital.azure.org", "DOC-401"),
        ("nurse_sujan", hash_password("Nurse@123"), "Nurse Sujan Rao, RN", ROLE_NURSE, "Emergency & Triage", "nurse.sujan@hospital.azure.org", "NUR-702")
    ]

    cursor.executemany("""
    INSERT INTO users (username, password_hash, full_name, role, department, email, badge_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, [(u[0], u[1], u[2], u[3], u[4], u[5], u[6], now) for u in users_data])

    # 2. Seed IP Firewall Subnets (Supports both Public Access and Hospital Subnet 192.168.10.0/24)
    firewall_rules = [
        ("0.0.0.0/0", "Public Internet Access (Global Network Whitelist - All IPs Allowed)", "ALLOW", 1),
        ("192.168.10.0/24", "St. Luke's Hospital Internal Network (Intranet & Clinical Wards)", "ALLOW", 1),
        ("10.0.0.0/16", "Azure Virtual Network (VNet) Internal Subnet", "ALLOW", 1),
        ("127.0.0.1/32", "Local Cloud VM Loopback Adapter", "ALLOW", 1)
    ]

    cursor.executemany("""
    INSERT INTO ip_firewall_rules (subnet_cidr, description, rule_type, is_active, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, [(r[0], r[1], r[2], r[3], now) for r in firewall_rules])

    # 3. Seed Patients
    patients_data = [
        ("MRN-2026-0811", "Rajesh Kumar", "1978-04-12", "Male", "O+", "+91-9845012345", "rajesh.k@gmail.com", "42 Brigade Rd, Bengaluru", "Sunita Kumar (Wife) +91-9845012346", "Penicillin, Sulfa drugs", "Hypertension Stage 2, Hyperlipidemia", "dr_suhas"),
        ("MRN-2026-0812", "Priya Sharma", "1994-09-25", "Female", "B+", "+91-9821098765", "priya.sharma@outlook.com", "18 Indiranagar, Bengaluru", "Ramesh Sharma (Father) +91-9821098760", "Latex, NSAIDs", "Asthma, Seasonal Rhinitis", "nurse_sujan"),
        ("MRN-2026-0813", "Anita Desai", "1965-11-03", "Female", "A-", "+91-9740112233", "anita.desai@yahoo.com", "77 Malleshwaram, Bengaluru", "Karan Desai (Son) +91-9740112234", "Aspirin, Shellfish", "Post-Coronary Angioplasty (2024), Type 2 Diabetes", "dr_suhas"),
        ("MRN-2026-0814", "Mohammed Farooq", "1983-02-18", "Male", "AB+", "+91-9988776655", "m.farooq@company.com", "12 Koramangala, Bengaluru", "Amina Farooq (Spouse) +91-9988776650", "None known", "Chronic Kidney Disease Stage 2", "dr_suhas")
    ]

    cursor.executemany("""
    INSERT INTO patients (mrn, full_name, dob, gender, blood_group, phone, email, address, emergency_contact, allergies, chronic_conditions, created_at, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], now, p[11]) for p in patients_data])

    conn.commit()

    # Get IDs
    cursor.execute("SELECT id, mrn FROM patients")
    patients_map = {row["mrn"]: row["id"] for row in cursor.fetchall()}

    cursor.execute("SELECT id, username FROM users")
    users_map = {row["username"]: row["id"] for row in cursor.fetchall()}

    # 4. Seed Clinical Notes / Triage Vitals
    p1_id = patients_map["MRN-2026-0811"]
    p2_id = patients_map["MRN-2026-0812"]
    p3_id = patients_map["MRN-2026-0813"]

    clinical_entries = [
        (p1_id, users_map["nurse_sujan"], "Nurse Sujan Rao, RN", ROLE_NURSE, "Triage & Vitals", 
         "Patient arrived complaining of intermittent chest tightness and mild dyspnea upon exertion. Conscious and oriented.", 
         json.dumps({"BP": "148/92 mmHg", "HeartRate": "84 bpm", "SpO2": "98%", "Temp": "98.4 F", "Weight": "76 kg"}), now),
        (p1_id, users_map["dr_suhas"], "Dr. Suhas Patil, MD", ROLE_DOCTOR, "Physician Assessment", 
         "Evaluated 48yo male with recurrent angina symptoms. ECG demonstrates mild ST elevation in leads V3-V4. Initiated Cardivas 12.5mg OD, Atorvastatin 40mg. Scheduled stress echo.", 
         json.dumps({"Diagnosis": "Coronary Artery Disease Suspicion", "Auscultation": "Normal S1/S2", "Action": "Stat Echocardiogram"}), now),
        (p2_id, users_map["nurse_sujan"], "Nurse Sujan Rao, RN", ROLE_NURSE, "Routine Checkup", 
         "Routine asthma follow-up. Peak flow measured at 420 L/min. Patient tolerates Budesonide inhaler well.", 
         json.dumps({"BP": "118/76 mmHg", "HeartRate": "72 bpm", "SpO2": "99%", "PeakFlow": "420 L/min"}), now),
        (p3_id, users_map["dr_suhas"], "Dr. Suhas Patil, MD", ROLE_DOCTOR, "Cardiology Follow-up", 
         "61yo female status-post DES stenting. Stable hemodynamics. Renal panel satisfactory. Encouraged salt restriction and regular walking.", 
         json.dumps({"BP": "124/80 mmHg", "HeartRate": "68 bpm", "HbA1c": "6.8%"}), now)
    ]

    cursor.executemany("""
    INSERT INTO clinical_notes (patient_id, author_id, author_name, author_role, note_type, content, vitals_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, clinical_entries)

    conn.commit()

    # 5. Initialize Storage Engine and Seed Encrypted Medical Report Blobs
    storage = AzureBlobStorageEngine()

    reports_to_create = [
        {
            "patient_mrn": "MRN-2026-0811",
            "title": "Comprehensive Lipid & Cardiac Biomarker Panel",
            "category": "Laboratory",
            "file_name": "Lipid_Cardiac_Panel_MRN20260811.txt",
            "mime_type": "text/plain",
            "uploader_username": "dr_suhas",
            "uploader_name": "Dr. Suhas Patil, MD",
            "uploader_role": ROLE_DOCTOR,
            "doctor_verified": 1,
            "notes": "Elevated LDL (164 mg/dL) and Total Cholesterol (242 mg/dL). Troponin-I negative.",
            "content": """===============================================================
ST. LUKE'S MEDICAL CENTER - CLINICAL LABORATORY REPORT
CONFIDENTIAL HEALTHCARE RECORD - PROTECTED BY HIPAA / AZURE BLOB SSE
===============================================================
Patient: Rajesh Kumar | MRN: MRN-2026-0811 | DOB: 1978-04-12
Ordering Physician: Dr. Suhas Patil, MD (Cardiovascular)
Collection Date: 2026-11-20 08:30 IST

TEST DESCRIPTION               RESULT        REFERENCE RANGE    STATUS
-----------------------------------------------------------------
Total Cholesterol              242 mg/dL     < 200 mg/dL        HIGH
HDL Cholesterol                41 mg/dL      > 40 mg/dL         NORMAL
LDL Cholesterol (Calculated)   164 mg/dL     < 100 mg/dL        HIGH
Triglycerides                  185 mg/dL     < 150 mg/dL        BORDERLINE
High Sensitivity CRP (hs-CRP)  3.4 mg/L      < 1.0 mg/L         ELEVATED
Cardiac Troponin-I             < 0.01 ng/mL  < 0.04 ng/mL       NORMAL
Fasting Blood Sugar            108 mg/dL     70 - 99 mg/dL      ELEVATED
Serum Creatinine               1.02 mg/dL    0.7 - 1.3 mg/dL    NORMAL

INTERPRETATION:
Evidence of moderate dyslipidemia and systemic vascular inflammation.
Cardiovascular risk profile: Moderate-High.
Recommendation: Initiate HMG-CoA reductase inhibitor (Atorvastatin 40mg), dietary modification.
Authorized by: Dr. Suhas Patil, MD
==============================================================="""
        },
        {
            "patient_mrn": "MRN-2026-0811",
            "title": "2D Transthoracic Echocardiogram Report",
            "category": "Cardiology",
            "file_name": "Echo_Study_MRN20260811.txt",
            "mime_type": "text/plain",
            "uploader_username": "dr_suhas",
            "uploader_name": "Dr. Suhas Patil, MD",
            "uploader_role": ROLE_DOCTOR,
            "doctor_verified": 1,
            "notes": "LVEF estimated at 55%. Concentric LV hypertrophy noted. No regional wall motion abnormalities.",
            "content": """===============================================================
ST. LUKE'S CARDIOLOGY INSTITUTE - ULTRASOUND & ECHO DIVISION
AZURE ENCRYPTED OBJECT STORAGE VAULT
===============================================================
Patient: Rajesh Kumar | MRN: MRN-2026-0811
Referring Doctor: Dr. Suhas Patil, MD
Date of Examination: 2026-11-21 11:15 IST

FINDINGS:
1. Left Ventricle: Concentric left ventricular hypertrophy. Normal LV cavity dimensions.
   Estimated Left Ventricular Ejection Fraction (LVEF): 55-60%.
2. Right Ventricle: Normal size and systolic function (TAPSE 2.2 cm).
3. Atria: Left atrium mildly dilated (LAVI 36 ml/m²). Right atrium normal.
4. Valves:
   - Mitral Valve: Mild mitral regurgitation, E/A ratio 0.8 (Impaired relaxation pattern).
   - Aortic Valve: Trileaflet, no significant stenosis or regurgitation.
   - Tricuspid Valve: Trivial regurgitation, estimated PASP 28 mmHg (Normal).
5. Pericardium: No pericardial effusion.

IMPRESSION:
Grade 1 Diastolic Dysfunction with concentric LVH secondary to systemic hypertension.
Preserved systolic ejection fraction.
Signed: Dr. Suhas Patil, MD (Consultant Cardiologist)
==============================================================="""
        },
        {
            "patient_mrn": "MRN-2026-0812",
            "title": "Complete Blood Count & Allergy IgE Panel",
            "category": "Laboratory",
            "file_name": "CBC_Allergy_PriyaSharma.txt",
            "mime_type": "text/plain",
            "uploader_username": "nurse_sujan",
            "uploader_name": "Nurse Sujan Rao, RN",
            "uploader_role": ROLE_NURSE,
            "doctor_verified": 0,
            "notes": "Eosinophil count moderately elevated (7.2%). Total IgE 480 IU/mL confirming allergic diathesis.",
            "content": """===============================================================
ST. LUKE'S PATHOLOGY - IMMUNOLOGY & HEMATOLOGY UNIT
STORED VIA SECURE BLOB CONTAINER: patient-medical-records
===============================================================
Patient: Priya Sharma | MRN: MRN-2026-0812 | Age: 32 / Female
Nurse in Charge: Nurse Sujan Rao, RN
Sample Received: 2026-11-21 09:00 IST

HEMATOLOGY (CBC):
Hemoglobin: 13.2 g/dL (12.0 - 15.5)
RBC Count: 4.5 x10^12/L (4.0 - 5.2)
WBC Count: 8,400 /uL (4,500 - 11,000)
Platelet Count: 260,000 /uL (150,000 - 450,000)
Differential:
 - Neutrophils: 58%
 - Lymphocytes: 31%
 - Eosinophils: 7.2% [ELEVATED]
 - Monocytes: 3.5%

ALLERGOLOGY:
Total Serum IgE: 480 IU/mL [HIGH - Normal < 100 IU/mL]
Specific Allergen Screen:
 - Dust Mite (D. pteronyssinus): Class 3 (High)
 - Pollen Mix: Class 2 (Moderate)
 - Latex: Class 1 (Low sensitivity)

Nurse Notes: Uploaded routine pre-consultation lab sheet.
Logged by Nurse Sujan Rao, RN
==============================================================="""
        },
        {
            "patient_mrn": "MRN-2026-0813",
            "title": "Coronary CT Angiography Follow-up",
            "category": "Radiology",
            "file_name": "Coronary_CT_Angio_AnitaDesai.txt",
            "mime_type": "text/plain",
            "uploader_username": "dr_suhas",
            "uploader_name": "Dr. Suhas Patil, MD",
            "uploader_role": ROLE_DOCTOR,
            "doctor_verified": 1,
            "notes": "Patent stent in proximal LAD. No in-stent restenosis. Distal vessels widely patent.",
            "content": """===============================================================
DEPARTMENT OF DIAGNOSTIC RADIOLOGY & CARDIOVASCULAR IMAGING
AZURE STORAGE CONTAINER BLOB RECORD
===============================================================
Patient: Anita Desai | MRN: MRN-2026-0813 | Age: 61
Referring Physician: Dr. Suhas Patil, MD
Scan Protocol: 128-Slice Dual-Source Coronary CT Angiography
Contrast: Omnipaque 350 (65 mL IV)

OBSERVATIONS:
- Left Main: Normal branching, calcium score = 0.
- Left Anterior Descending (LAD): Previously placed drug-eluting stent in proximal segment is fully expanded and patent. No intraluminal neointimal hyperplasia. Contrast opacifies distal bed freely.
- Left Circumflex (LCx): Minor 15% calcified eccentric plaque, non-hemodynamically significant.
- Right Coronary Artery (RCA): Normal vessel course, mild wall irregularities.

CONCLUSION:
Uncomplicated follow-up post-PCI. Patent LAD stent. Excellent prognostic stability.
Verified by: Dr. Suhas Patil, MD
==============================================================="""
        }
    ]

    for rep in reports_to_create:
        rep_uuid = str(uuid.uuid4())
        blob_name = f"blob-{rep['patient_mrn']}-{rep_uuid[:8]}.dat"
        data_bytes = rep["content"].encode('utf-8')

        # Store in encrypted Azure Blob Storage
        meta_res = storage.upload_blob(blob_name, data_bytes, metadata={
            "patient_mrn": rep["patient_mrn"],
            "title": rep["title"],
            "category": rep["category"],
            "uploader": rep["uploader_username"]
        })

        patient_id = patients_map[rep["patient_mrn"]]
        uploader_id = users_map[rep["uploader_username"]]

        cursor.execute("""
        INSERT INTO medical_reports (
            report_uuid, patient_id, title, category, file_name, file_size, 
            mime_type, blob_name, encryption_algorithm, sha256_hash, 
            uploader_id, uploader_name, uploader_role, notes, doctor_verified, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rep_uuid, patient_id, rep["title"], rep["category"], rep["file_name"],
            len(data_bytes), rep["mime_type"], blob_name, meta_res["encryption_algorithm"],
            meta_res["plaintext_sha256"], uploader_id, rep["uploader_name"], rep["uploader_role"],
            rep["notes"], rep["doctor_verified"], now
        ))

    conn.commit()

    # 6. Seed initial audit logs to simulate previous operations
    audit_events = [
        (users_map["admin"], "admin", ROLE_ADMIN, "192.168.10.10", "SYSTEM_INIT", "INFRASTRUCTURE", "AZURE_VM_01", "SUCCESS", "Provisioned Ubuntu 24.04 LTS Cloud VM and configured Azure Blob Storage with SSE"),
        (users_map["admin"], "admin", ROLE_ADMIN, "192.168.10.10", "FIREWALL_CONFIG", "SECURITY_GROUP", "SUBNET_192.168.10.0/24", "SUCCESS", "Configured Hospital Internal Subnet whitelist 192.168.10.0/24"),
        (users_map["dr_suhas"], "dr_suhas", ROLE_DOCTOR, "192.168.10.45", "LOGIN", "AUTH", "DOC-401", "SUCCESS", "Dr. Suhas Patil logged in from Hospital Consultant Room 4A"),
        (users_map["dr_suhas"], "dr_suhas", ROLE_DOCTOR, "192.168.10.45", "ENCRYPT_UPLOAD", "MEDICAL_REPORT", "MRN-2026-0811", "SUCCESS", "Uploaded & Encrypted Echo Study with AES-256-GCM"),
        (users_map["nurse_sujan"], "nurse_sujan", ROLE_NURSE, "192.168.10.82", "LOGIN", "AUTH", "NUR-702", "SUCCESS", "Nurse Sujan Rao logged in from Emergency Triage Station"),
        (users_map["nurse_sujan"], "nurse_sujan", ROLE_NURSE, "192.168.10.82", "ENCRYPT_UPLOAD", "MEDICAL_REPORT", "MRN-2026-0812", "SUCCESS", "Uploaded CBC and Allergy Panel to secure blob storage"),
        (None, "UNKNOWN_ATTACKER", "ANONYMOUS", "203.0.113.88", "BLOCKED_ACCESS_ATTEMPT", "MEDICAL_RECORD", "MRN-2026-0811", "BLOCKED", "Firewall blocked unauthorized external IP 203.0.113.88 attempting direct report download")
    ]

    cursor.executemany("""
    INSERT INTO audit_logs (user_id, username, role, client_ip, action, resource_type, resource_id, status, details, timestamp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], (datetime.now(timezone.utc) - timedelta(minutes=15 * (7 - idx))).isoformat()) for idx, a in enumerate(audit_events)])

    conn.commit()
    conn.close()
    print("Database seeded successfully with Users, Hospital IP Rules, Patients, Notes, Encrypted Blobs, and Audit Logs.")

if __name__ == "__main__":
    seed_database()
