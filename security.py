# Security & Firewall Engine for Medical Records Storage System
# Assignment 15: Suhas & Sujan - IP Security & Role-Based Access Control (RBAC)

import ipaddress
import hashlib
import functools
from flask import request, jsonify, session

# Role definitions
ROLE_ADMIN = "ADMIN"
ROLE_DOCTOR = "DOCTOR"
ROLE_NURSE = "NURSE"

VALID_ROLES = [ROLE_ADMIN, ROLE_DOCTOR, ROLE_NURSE]

# Role Permissions Matrix
ROLE_PERMISSIONS = {
    ROLE_ADMIN: {
        "can_view_patients": True,
        "can_register_patients": True,
        "can_view_reports": True,
        "can_upload_reports": True,
        "can_download_reports": True,
        "can_manage_users": True,
        "can_manage_firewall": True,
        "can_view_audit_logs": True,
        "can_edit_clinical_notes": False, # Clinical ethics segregation
        "requires_hospital_ip_for_reports": False # Admin console can be configured with dual-factor/VPN
    },
    ROLE_DOCTOR: {
        "can_view_patients": True,
        "can_register_patients": True,
        "can_view_reports": True,
        "can_upload_reports": True,
        "can_download_reports": True,
        "can_manage_users": False,
        "can_manage_firewall": False,
        "can_view_audit_logs": True,
        "can_edit_clinical_notes": True,
        "requires_hospital_ip_for_reports": True # As per Assignment 15 specification: IP restrictions
    },
    ROLE_NURSE: {
        "can_view_patients": True,
        "can_register_patients": True,
        "can_view_reports": True,
        "can_upload_reports": True, # Can upload routine vitals and lab panels
        "can_download_reports": False, # Restrict mass PHI report export to Doctors/Admins
        "can_manage_users": False,
        "can_manage_firewall": False,
        "can_view_audit_logs": False,
        "can_edit_clinical_notes": True, # Triage & Vitals
        "requires_hospital_ip_for_reports": True # Protected by IP restrictions
    }
}

def hash_password(password: str, salt: str = "suhas_sujan_salt_2026") -> str:
    """Hashes password with SHA-256 and custom salt"""
    return hashlib.sha256(f"{password}:{salt}".encode('utf-8')).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def get_client_ip(req) -> str:
    """
    Retrieves effective client IP address.
    Checks for:
    1. Session simulated IP (for live demonstrations & testing)
    2. HTTP header 'X-Forwarded-For'
    3. HTTP header 'X-Real-IP'
    4. Direct socket remote_addr
    """
    simulated_ip = session.get("simulated_ip")
    if simulated_ip:
        return simulated_ip
    
    header_ip = req.headers.get("X-Forwarded-For")
    if header_ip:
        return header_ip.split(",")[0].strip()
    
    real_ip = req.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return req.remote_addr or "127.0.0.1"

def is_ip_in_network(ip_str: str, network_cidr: str) -> bool:
    """Checks if an IPv4/IPv6 address falls within a CIDR subnet"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Handle ipv6-mapped ipv4 like ::ffff:127.0.0.1
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        net = ipaddress.ip_network(network_cidr, strict=False)
        return ip in net
    except ValueError:
        return False

def evaluate_ip_access(client_ip: str, allowed_subnets: list, user_role: str = None) -> dict:
    """
    Evaluates whether the client IP address is allowed access to medical records.
    Assignment 15 Requirement:
      Hospital Network: 192.168.10.0/24
      Allowed: Doctors / Hospital Staff
      Denied: External IPs
    """
    # Normalize IP
    try:
        parsed_ip = ipaddress.ip_address(client_ip)
        if parsed_ip.version == 6 and parsed_ip.ipv4_mapped:
            client_ip = str(parsed_ip.ipv4_mapped)
    except ValueError:
        return {
            "allowed": False,
            "reason": f"Invalid IP address format: {client_ip}",
            "client_ip": client_ip,
            "matched_rule": None
        }

    # Evaluate against active allowed subnets
    for rule in allowed_subnets:
        cidr = rule.get("subnet_cidr") if isinstance(rule, dict) else rule
        rule_type = rule.get("rule_type", "ALLOW") if isinstance(rule, dict) else "ALLOW"
        
        if is_ip_in_network(client_ip, cidr):
            if rule_type == "ALLOW":
                return {
                    "allowed": True,
                    "reason": "Public Access Mode Active (0.0.0.0/0 - All Networks Allowed)" if cidr == "0.0.0.0/0" else f"Authorized Network Subnet ({cidr})",
                    "client_ip": client_ip,
                    "matched_rule": cidr,
                    "rule_type": "ALLOW"
                }
            else:
                return {
                    "allowed": False,
                    "reason": f"Explicitly Denied by Subnet Rule ({cidr})",
                    "client_ip": client_ip,
                    "matched_rule": cidr,
                    "rule_type": "DENY"
                }

    # Default Deny for External IPs
    return {
        "allowed": False,
        "reason": f"Access Denied: External IP ({client_ip}) is not within the authorized Hospital Subnet (192.168.10.0/24).",
        "client_ip": client_ip,
        "matched_rule": "DEFAULT_DENY_EXTERNAL"
    }

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"error": "Authentication required."}), 401
            user_role = session.get("role")
            if user_role not in allowed_roles:
                return jsonify({
                    "error": f"Access Forbidden: Role '{user_role}' does not have sufficient permissions. Required: {', '.join(allowed_roles)}"
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator
