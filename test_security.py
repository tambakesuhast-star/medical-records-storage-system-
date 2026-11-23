# Standalone Automated Test Runner for Assignment 15 Evaluation
# Assignment 15: Suhas & Sujan - Medical Records Storage System

import unittest
import json
import os
from app import app, storage
from models import get_db_connection, init_tables
from security import ROLE_ADMIN, ROLE_DOCTOR, ROLE_NURSE

class TestMedicalRecordsSecurity(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        init_tables()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = 'dr_suhas'")
        row = cursor.fetchone()
        self.doctor_id = row["id"] if row else 1

        cursor.execute("SELECT id FROM users WHERE username = 'nurse_sujan'")
        row_n = cursor.fetchone()
        self.nurse_id = row_n["id"] if row_n else 2
        conn.close()

    def test_01_doctor_access_hospital_ip_allowed(self):
        """Test that Doctor connecting from Hospital Network (192.168.10.45) is permitted"""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.doctor_id
            sess["username"] = "dr_suhas"
            sess["role"] = ROLE_DOCTOR
            sess["simulated_ip"] = "192.168.10.45"

        # Try to preview report #1
        res = self.client.get("/api/reports/1/preview")
        self.assertEqual(res.status_code, 200, "Doctor inside hospital subnet must have 200 OK access")
        data = json.loads(res.data)
        self.assertTrue(data.get("sha256_verified"), "Data integrity must be verified")

    def test_02_external_ip_access_blocked(self):
        """Test that client connecting from External Public IP (203.0.113.88) is blocked when in Hospital Restricted Mode"""
        # Temporarily deactivate 0.0.0.0/0 to test Hospital Subnet enforcement policy
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE ip_firewall_rules SET is_active = 0 WHERE subnet_cidr = '0.0.0.0/0'")
        conn.commit()
        conn.close()

        with self.client.session_transaction() as sess:
            sess["user_id"] = self.doctor_id
            sess["username"] = "dr_suhas"
            sess["role"] = ROLE_DOCTOR
            sess["simulated_ip"] = "203.0.113.88" # External untrusted IP

        # Attempt to download report
        res = self.client.get("/api/reports/1/download")
        self.assertEqual(res.status_code, 403, "External IP must be blocked with HTTP 403 Forbidden")
        data = json.loads(res.data)
        self.assertTrue(data.get("ip_restricted"), "Response must flag ip_restricted violation")

        # Restore public mode rule
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE ip_firewall_rules SET is_active = 1 WHERE subnet_cidr = '0.0.0.0/0'")
        conn.commit()
        conn.close()

    def test_03_nurse_rbac_download_restricted(self):
        """Test that Nurse role cannot perform mass raw report download/export"""
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.nurse_id
            sess["username"] = "nurse_sujan"
            sess["role"] = ROLE_NURSE
            sess["simulated_ip"] = "192.168.10.82" # Hospital IP

        res = self.client.get("/api/reports/1/download")
        self.assertEqual(res.status_code, 403, "Nurse role must be restricted from downloading raw files")

    def test_04_storage_encryption_at_rest(self):
        """Test that blob files on disk are truly AES-256 encrypted and not plaintext"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT blob_name FROM medical_reports LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row, "At least one report must exist in DB")
        blob_name = row["blob_name"]

        evidence = storage.get_encryption_evidence(blob_name)
        self.assertEqual(evidence["encryption_standard"], "AES-256-GCM (Authenticated Encryption)")
        self.assertEqual(evidence["status"], "ENCRYPTED_AT_REST")

        # Read actual disk file
        disk_path = os.path.join(storage.blobs_dir, f"{blob_name}.enc")
        self.assertTrue(os.path.exists(disk_path), "Encrypted file must exist in blob storage")
        with open(disk_path, "rb") as f:
            raw_bytes = f.read()

        # Verify plaintext string is NOT in raw encrypted disk bytes
        self.assertNotIn(b"ST. LUKE'S MEDICAL CENTER", raw_bytes, "Disk blob must not contain plaintext PHI strings!")

    def test_05_data_integrity_sha256_match(self):
        """Test that decrypted payload matches pre-encryption SHA-256 hash"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT blob_name, sha256_hash FROM medical_reports LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        decrypted_bytes, meta = storage.download_blob(row["blob_name"])
        self.assertEqual(meta["plaintext_sha256"], row["sha256_hash"], "SHA-256 hashes must match perfectly")

    def test_06_audit_logging_active(self):
        """Test that security events are logged into the audit trail"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE status = 'BLOCKED'")
        blocked_count = cursor.fetchone()["count"]
        conn.close()
        self.assertGreaterEqual(blocked_count, 1, "Audit logs must record blocked attempts")

if __name__ == "__main__":
    print("=" * 65)
    print("RUNNING SECURITY TEST SUITE")
    print("=" * 65)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestMedicalRecordsSecurity)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\nALL SECURITY TESTS PASSED SUCCESSFULLY! (100% COMPLIANCE)")
    else:
        print("\nSOME TESTS FAILED.")
