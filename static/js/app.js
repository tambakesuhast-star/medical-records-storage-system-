// St. Luke's Health Cloud - Frontend Client Logic
// Assignment 15: Suhas & Sujan - Medical Records Storage System

let currentUser = null;
let currentClientIp = "192.168.10.45";
let isHospitalSubnet = true;
let isPublicMode = true;
let allPatients = [];

document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

async function initApp() {
    await fetchCurrentUser();
    await fetchPublicMode();
    await loadDashboardStats();
    await loadPatients();
    await loadReports();
    await loadFirewallRules();
    await loadAuditLogs();
}

async function fetchPublicMode() {
    try {
        const res = await fetch("/api/security/public_mode");
        const data = await res.json();
        isPublicMode = data.public_mode;
        updatePublicModeUI(isPublicMode);
    } catch (e) {
        console.error("Error fetching public mode:", e);
    }
}

async function togglePublicMode() {
    try {
        const res = await fetch("/api/security/toggle_public_mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await res.json();
        isPublicMode = data.public_mode;
        updatePublicModeUI(isPublicMode);
        await fetchCurrentUser();
        await loadFirewallRules();
        await loadAuditLogs();
        showToast(data.message, isPublicMode ? "success" : "warning");
    } catch (e) {
        showToast("Error updating public mode", "error");
    }
}

function updatePublicModeUI(enabled) {
    const headerBtn = document.getElementById("publicModeHeaderBtn");
    const headerStatus = document.getElementById("publicModeHeaderStatus");
    const tabBtn = document.getElementById("publicModeTabBtn");
    const tabText = document.getElementById("publicModeTabBtnText");

    if (enabled) {
        if (headerBtn) {
            headerBtn.className = "flex items-center px-3 py-1.5 rounded-lg bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-300 text-xs font-semibold shadow-sm transition";
        }
        if (headerStatus) headerStatus.textContent = "Public Access: ON";
        if (tabBtn) {
            tabBtn.className = "px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs shadow-sm transition flex items-center space-x-1.5";
        }
        if (tabText) tabText.textContent = "Public Access: ENABLED";
    } else {
        if (headerBtn) {
            headerBtn.className = "flex items-center px-3 py-1.5 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-300 text-xs font-semibold shadow-sm transition";
        }
        if (headerStatus) headerStatus.textContent = "Public Access: OFF (Hospital Only)";
        if (tabBtn) {
            tabBtn.className = "px-3.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-bold text-xs shadow-sm transition flex items-center space-x-1.5";
        }
        if (tabText) tabText.textContent = "Public Access: RESTRICTED";
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied ${text} to clipboard!`, "success");
    }).catch(() => {
        showToast("Could not copy to clipboard", "warning");
    });
}

// =========================================================================
// TAB SWITCHING
// =========================================================================

function switchTab(tabName) {
    const panes = [
        'dashboard', 'patients', 'records', 'ipsecurity', 
        'tests', 'architecture', 'audit', 'deliverables'
    ];
    panes.forEach(pane => {
        const el = document.getElementById(`pane-${pane}`);
        const btn = document.getElementById(`tab-${pane}`);
        if (el) el.classList.add('hidden');
        if (btn) btn.classList.remove('active');
    });

    const targetPane = document.getElementById(`pane-${tabName}`);
    const targetBtn = document.getElementById(`tab-${tabName}`);
    if (targetPane) targetPane.classList.remove('hidden');
    if (targetBtn) targetBtn.classList.add('active');

    if (tabName === 'dashboard') loadDashboardStats();
    if (tabName === 'patients') loadPatients();
    if (tabName === 'records') loadReports();
    if (tabName === 'ipsecurity') loadFirewallRules();
    if (tabName === 'audit') loadAuditLogs();
}

// =========================================================================
// AUTHENTICATION & USER PROFILE
// =========================================================================

async function fetchCurrentUser() {
    try {
        const res = await fetch("/api/auth/current_user");
        const data = await res.json();
        if (data.authenticated) {
            currentUser = data.user;
            currentClientIp = data.client_ip;
            isHospitalSubnet = data.ip_evaluation.allowed;

            // Update UI elements
            const selector = document.getElementById("userRoleSelector");
            if (selector) selector.value = currentUser.role;

            updateIpDisplay(data.client_ip, isHospitalSubnet);
        }
    } catch (e) {
        console.error("Error fetching current user:", e);
    }
}

async function switchDemoRole(role) {
    try {
        const res = await fetch("/api/auth/switch_demo_user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ role: role })
        });
        const data = await res.json();
        if (data.success) {
            await fetchCurrentUser();
            await loadDashboardStats();
            await loadPatients();
            await loadReports();
            await loadAuditLogs();
            showToast(`Switched active profile to ${data.user.full_name} (${data.user.role})`, "success");
        }
    } catch (e) {
        showToast("Failed to switch role", "error");
    }
}

// =========================================================================
// IP RESTRICTION & SIMULATION CONTROLS
// =========================================================================

async function setSimulationIp(ip) {
    try {
        const res = await fetch("/api/security/set_simulated_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip })
        });
        const data = await res.json();
        if (data.success) {
            currentClientIp = data.active_ip;
            isHospitalSubnet = data.evaluation.allowed;
            updateIpDisplay(data.active_ip, isHospitalSubnet);
            await loadDashboardStats();
            await loadReports();
            await loadAuditLogs();

            if (isHospitalSubnet) {
                showToast(`Connected to Hospital Subnet (${data.active_ip}). Patient record access: ALLOWED.`, "success");
            } else {
                showToast(`Connected via External IP (${data.active_ip}). Patient record access: BLOCKED by Firewall policy.`, "warning");
            }
        }
    } catch (e) {
        showToast("Error updating IP simulation", "error");
    }
}

function updateIpDisplay(ip, allowed) {
    const displayIp = document.getElementById("displayClientIp");
    const dot = document.getElementById("ipIndicatorDot");
    const warningBanner = document.getElementById("externalIpWarningBanner");
    const bannerIpText = document.getElementById("bannerIpText");
    const fwIp = document.getElementById("firewallCurrentIp");
    const fwDec = document.getElementById("firewallDecisionText");
    const fwRea = document.getElementById("firewallDecisionReason");

    if (displayIp) displayIp.textContent = ip;
    if (fwIp) fwIp.textContent = ip;

    if (allowed) {
        if (dot) dot.className = "w-2.5 h-2.5 rounded-full bg-emerald-500 mr-2";
        if (warningBanner) warningBanner.classList.add("hidden");
        if (fwDec) {
            fwDec.textContent = "ALLOWED (Hospital Subnet)";
            fwDec.className = "text-lg font-bold mt-1 text-emerald-600";
        }
        if (fwRea) fwRea.textContent = "Authorized Subnet 192.168.10.0/24 - Full medical data access permitted.";
    } else {
        if (dot) dot.className = "w-2.5 h-2.5 rounded-full bg-rose-500 mr-2 animate-ping";
        if (warningBanner) {
            warningBanner.classList.remove("hidden");
            if (bannerIpText) bannerIpText.textContent = ip;
        }
        if (fwDec) {
            fwDec.textContent = "BLOCKED (External IP)";
            fwDec.className = "text-lg font-bold mt-1 text-rose-600";
        }
        if (fwRea) fwRea.textContent = "External untrusted network. Confidential reports blocked by Hospital Subnet policy.";
    }
}

// =========================================================================
// DASHBOARD STATS
// =========================================================================

async function loadDashboardStats() {
    try {
        const res = await fetch("/api/system/status");
        const data = await res.json();
        
        document.getElementById("statPatientsCount").textContent = data.metrics.total_patients;
        document.getElementById("statBlobsCount").textContent = data.metrics.total_encrypted_blobs;
        document.getElementById("statBlockedCount").textContent = data.metrics.security_blocks;
    } catch (e) {
        console.error("Error loading dashboard stats:", e);
    }
}

// =========================================================================
// PATIENTS REGISTRY
// =========================================================================

async function loadPatients(query = "") {
    try {
        const url = query ? `/api/patients?q=${encodeURIComponent(query)}` : "/api/patients";
        const res = await fetch(url);
        const data = await res.json();
        allPatients = data.patients || [];

        const tbody = document.getElementById("patientsTableBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        // Also update select option in upload modal
        const uploadSelect = document.getElementById("uploadPatientId");
        if (uploadSelect) {
            uploadSelect.innerHTML = allPatients.map(p => `<option value="${p.id}">${p.full_name} (${p.mrn})</option>`).join("");
        }

        if (allPatients.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-slate-400">No patient records found.</td></tr>`;
            return;
        }

        allPatients.forEach(p => {
            const tr = document.createElement("tr");
            tr.className = "hover:bg-slate-50 transition border-b border-slate-100";
            tr.innerHTML = `
                <td class="p-3.5 font-mono font-bold text-teal-700">${p.mrn}</td>
                <td class="p-3.5 font-semibold text-slate-900">${p.full_name}</td>
                <td class="p-3.5 text-slate-600">${p.dob} (${calculateAge(p.dob)} yrs, ${p.gender})</td>
                <td class="p-3.5"><span class="px-2 py-0.5 rounded font-bold bg-rose-50 text-rose-700 border border-rose-200">${p.blood_group}</span></td>
                <td class="p-3.5 text-slate-700">${p.chronic_conditions || 'None'}</td>
                <td class="p-3.5 text-amber-700">${p.allergies || 'None'}</td>
                <td class="p-3.5">
                    <span class="px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-semibold border border-blue-200">
                        <i class="fa-solid fa-lock text-[10px] mr-1"></i> ${p.report_count} Blobs
                    </span>
                </td>
                <td class="p-3.5 text-right space-x-1">
                    <button onclick="viewPatientHistory(${p.id})" class="px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded font-medium transition" title="View Medical History">
                        <i class="fa-solid fa-clock-rotate-left mr-1"></i> History
                    </button>
                    <button onclick="openUploadForPatient(${p.id})" class="px-2.5 py-1 bg-teal-50 hover:bg-teal-100 text-teal-700 rounded font-medium border border-teal-200 transition" title="Upload New Encrypted Report">
                        <i class="fa-solid fa-cloud-arrow-up mr-1"></i> Upload
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading patients:", e);
    }
}

function calculateAge(dobStr) {
    if (!dobStr) return "N/A";
    const dob = new Date(dobStr);
    const diffMs = Date.now() - dob.getTime();
    const ageDt = new Date(diffMs);
    return Math.abs(ageDt.getUTCFullYear() - 1970);
}

function openRegisterPatientModal() {
    document.getElementById("registerPatientModal").classList.remove("hidden");
}

async function submitPatientRegistration(e) {
    e.preventDefault();
    const payload = {
        full_name: document.getElementById("regFullName").value.trim(),
        dob: document.getElementById("regDob").value,
        gender: document.getElementById("regGender").value,
        blood_group: document.getElementById("regBlood").value,
        phone: document.getElementById("regPhone").value.trim(),
        emergency_contact: document.getElementById("regEmergency").value.trim(),
        allergies: document.getElementById("regAllergies").value.trim(),
        chronic_conditions: document.getElementById("regConditions").value.trim()
    };

    try {
        const res = await fetch("/api/patients", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok) {
            closeModal("registerPatientModal");
            document.getElementById("registerPatientForm").reset();
            showToast(data.message, "success");
            await loadPatients();
            await loadDashboardStats();
            await loadAuditLogs();
        } else {
            showToast(data.error || "Failed to register patient", "error");
        }
    } catch (err) {
        showToast("Registration network error", "error");
    }
}

async function viewPatientHistory(patientId) {
    try {
        const res = await fetch(`/api/patients/${patientId}`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        const patient = data.patient;
        document.getElementById("historyPatientName").textContent = `${patient.full_name} (${patient.gender}, ${calculateAge(patient.dob)} yrs)`;
        document.getElementById("historyPatientMrn").textContent = `MRN: ${patient.mrn} | Blood: ${patient.blood_group} | Allergies: ${patient.allergies}`;

        const container = document.getElementById("historyTimelineContent");
        container.innerHTML = "";

        // Display Clinical Notes
        if (data.notes && data.notes.length > 0) {
            data.notes.forEach(note => {
                let vitalsHtml = "";
                if (note.vitals_json) {
                    try {
                        const vitals = JSON.parse(note.vitals_json);
                        vitalsHtml = `<div class="mt-2 grid grid-cols-3 gap-2 bg-slate-50 p-2 rounded text-[11px] font-mono">` +
                            Object.entries(vitals).map(([k, v]) => `<div><span class="text-slate-400">${k}:</span> <strong class="text-slate-800">${v}</strong></div>`).join("") +
                            `</div>`;
                    } catch (e) {}
                }

                const item = document.createElement("div");
                item.className = "p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-1";
                item.innerHTML = `
                    <div class="flex justify-between items-center text-slate-500 text-[11px]">
                        <span class="font-bold text-teal-800">${note.note_type}</span>
                        <span>${new Date(note.created_at).toLocaleString()}</span>
                    </div>
                    <div class="text-slate-800 text-xs">${note.content}</div>
                    ${vitalsHtml}
                    <div class="text-[10px] text-slate-400 text-right">Recorded by: ${note.author_name} (${note.author_role})</div>
                `;
                container.appendChild(item);
            });
        }

        // Display Associated Reports
        if (data.reports && data.reports.length > 0) {
            const reportHeader = document.createElement("div");
            reportHeader.className = "font-bold text-slate-800 text-xs mt-3 pt-2 border-t border-slate-200 flex items-center justify-between";
            reportHeader.innerHTML = `<span>Encrypted Reports in Object Storage (${data.reports.length})</span>`;
            container.appendChild(reportHeader);

            data.reports.forEach(rep => {
                const repCard = document.createElement("div");
                repCard.className = "p-3 bg-teal-50/50 rounded-xl border border-teal-200 flex justify-between items-center";
                repCard.innerHTML = `
                    <div>
                        <div class="font-semibold text-slate-900">${rep.title}</div>
                        <div class="text-[11px] text-slate-500 font-mono">${rep.file_name} • ${rep.category} • ${rep.encryption_algorithm}</div>
                    </div>
                    <div class="space-x-1">
                        <button onclick="previewReport(${rep.id})" class="px-2 py-1 bg-white hover:bg-slate-100 text-slate-700 rounded border border-slate-200 text-[11px]">
                            <i class="fa-solid fa-eye text-teal-600"></i>
                        </button>
                        <button onclick="downloadReport(${rep.id})" class="px-2 py-1 bg-teal-600 hover:bg-teal-700 text-white rounded text-[11px]">
                            <i class="fa-solid fa-download"></i>
                        </button>
                    </div>
                `;
                container.appendChild(repCard);
            });
        }

        document.getElementById("historyModal").classList.remove("hidden");
    } catch (err) {
        showToast("Error retrieving patient history", "error");
    }
}

// =========================================================================
// MEDICAL REPORTS & OBJECT STORAGE (AES-256)
// =========================================================================

async function loadReports() {
    try {
        const res = await fetch("/api/patients");
        const data = await res.json();
        const patients = data.patients || [];

        const tbody = document.getElementById("reportsTableBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        let allReports = [];
        for (const p of patients) {
            const pRes = await fetch(`/api/patients/${p.id}`);
            const pData = await pRes.json();
            if (pData.reports) {
                pData.reports.forEach(r => {
                    r.patient_name = p.full_name;
                    r.patient_mrn = p.mrn;
                    allReports.push(r);
                });
            }
        }

        if (allReports.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="p-6 text-center text-slate-400">No medical reports in storage container.</td></tr>`;
            return;
        }

        allReports.forEach(r => {
            const tr = document.createElement("tr");
            tr.className = "hover:bg-slate-50 transition border-b border-slate-100";
            tr.innerHTML = `
                <td class="p-3 font-semibold text-slate-900">
                    <div>${r.title}</div>
                    <div class="text-[10px] text-slate-400 font-mono">${r.file_name} (${(r.file_size / 1024).toFixed(1)} KB)</div>
                </td>
                <td class="p-3">
                    <span class="font-medium text-slate-800">${r.patient_name}</span>
                    <div class="text-[10px] text-slate-500 font-mono">${r.patient_mrn}</div>
                </td>
                <td class="p-3"><span class="px-2 py-0.5 rounded font-medium bg-slate-100 text-slate-700">${r.category}</span></td>
                <td class="p-3 font-mono text-[11px] text-blue-700">${r.blob_name}</td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 font-semibold border border-emerald-200">
                        <i class="fa-solid fa-lock text-[10px] mr-1"></i> ${r.encryption_algorithm}
                    </span>
                </td>
                <td class="p-3 text-slate-600">${r.uploader_name} <span class="text-[10px] text-slate-400">(${r.uploader_role})</span></td>
                <td class="p-3 font-mono text-[10px] text-slate-500" title="${r.sha256_hash}">${r.sha256_hash.substring(0, 10)}...</td>
                <td class="p-3 text-right space-x-1 whitespace-nowrap">
                    <button onclick="showEncryptionEvidence(${r.id})" class="px-2 py-1 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 rounded font-semibold border border-emerald-300 transition" title="View AES-256 Encryption Proof">
                        <i class="fa-solid fa-shield-halved mr-1"></i> Proof
                    </button>
                    <button onclick="previewReport(${r.id})" class="px-2 py-1 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded font-medium transition" title="Decrypt & View In-Browser">
                        <i class="fa-solid fa-eye mr-1"></i> View
                    </button>
                    <button onclick="downloadReport(${r.id})" class="px-2.5 py-1 bg-teal-600 hover:bg-teal-700 text-white rounded font-medium transition" title="Decrypt & Download (Enforces IP Check)">
                        <i class="fa-solid fa-download mr-1"></i> Download
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading reports:", e);
    }
}

function openUploadModal() {
    document.getElementById("uploadReportModal").classList.remove("hidden");
}

function openUploadForPatient(patientId) {
    openUploadModal();
    const select = document.getElementById("uploadPatientId");
    if (select) select.value = patientId;
}

async function submitReportUpload(e) {
    e.preventDefault();

    if (!isHospitalSubnet) {
        showToast("SECURITY BLOCK: Cannot upload patient reports from an External IP! Switch to Hospital Subnet.", "error");
        return;
    }

    const patientId = document.getElementById("uploadPatientId").value;
    const formData = new FormData();
    formData.append("title", document.getElementById("uploadTitle").value.trim());
    formData.append("category", document.getElementById("uploadCategory").value);
    formData.append("notes", document.getElementById("uploadNotes").value.trim());
    formData.append("text_content", document.getElementById("uploadTextContent").value.trim());

    const fileInput = document.getElementById("uploadFileInput");
    if (fileInput.files.length > 0) {
        formData.append("file", fileInput.files[0]);
    }

    try {
        const res = await fetch(`/api/patients/${patientId}/reports`, {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        if (res.ok) {
            closeModal("uploadReportModal");
            document.getElementById("uploadReportForm").reset();
            showToast(data.message, "success");
            await loadReports();
            await loadPatients();
            await loadDashboardStats();
            await loadAuditLogs();
        } else {
            showToast(data.error || "Report upload failed", "error");
        }
    } catch (err) {
        showToast("Upload network error", "error");
    }
}

async function previewReport(reportId) {
    try {
        const res = await fetch(`/api/reports/${reportId}/preview`);
        const data = await res.json();

        if (!res.ok) {
            if (res.status === 403 && data.ip_restricted) {
                showToast("ACCESS DENIED: External IP blocked from previewing patient reports!", "error");
            } else {
                showToast(data.error || "Failed to preview report", "error");
            }
            return;
        }

        document.getElementById("previewTitle").textContent = data.report.title;
        document.getElementById("previewSubtitle").textContent = `File: ${data.report.file_name} | Blob: ${data.report.blob_name} | Encrypted with AES-256-GCM`;
        document.getElementById("previewContentText").textContent = data.content;
        document.getElementById("previewModal").classList.remove("hidden");
    } catch (err) {
        showToast("Error retrieving decrypted preview", "error");
    }
}

async function downloadReport(reportId) {
    try {
        const res = await fetch(`/api/reports/${reportId}/download`);

        if (!res.ok) {
            const data = await res.json();
            if (res.status === 403) {
                showToast(`FIREWALL REJECTION: ${data.error}`, "error");
            } else {
                showToast(data.error || "Download denied", "error");
            }
            await loadAuditLogs();
            return;
        }

        const blob = await res.blob();
        const header = res.headers.get("content-disposition");
        let filename = "medical_report.txt";
        if (header && header.includes("filename=")) {
            filename = header.split("filename=")[1].replace(/['"]/g, '');
        }

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();

        showToast(`Successfully decrypted and downloaded ${filename}`, "success");
        await loadAuditLogs();
    } catch (err) {
        showToast("Download failed", "error");
    }
}

async function showEncryptionEvidence(reportId) {
    try {
        const res = await fetch(`/api/reports/${reportId}/encryption_evidence`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        const ev = data.evidence;
        document.getElementById("evidenceBlobName").textContent = data.blob_name;
        document.getElementById("evidenceAlgorithm").textContent = ev.encryption_standard;
        document.getElementById("evidenceKeyLength").textContent = ev.key_length;
        document.getElementById("evidencePlaintextSha").textContent = ev.plaintext_sha256;
        document.getElementById("evidenceCiphertextSha").textContent = ev.ciphertext_sha256;
        document.getElementById("evidenceNonce").textContent = ev.iv_nonce;
        document.getElementById("evidenceHexDump").textContent = ev.raw_hex_preview;
        document.getElementById("evidenceSasUrl").textContent = data.sas_url_simulation;

        document.getElementById("evidenceModal").classList.remove("hidden");
    } catch (err) {
        showToast("Error fetching encryption evidence", "error");
    }
}

// =========================================================================
// IP FIREWALL & SECURITY RULES
// =========================================================================

async function loadFirewallRules() {
    try {
        const res = await fetch("/api/security/rules");
        const data = await res.json();
        const rules = data.rules || [];

        const tbody = document.getElementById("firewallRulesTableBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        rules.forEach(r => {
            const tr = document.createElement("tr");
            tr.className = "hover:bg-slate-50 transition border-b border-slate-100";
            const isAllow = r.rule_type === "ALLOW";
            tr.innerHTML = `
                <td class="p-3 font-mono font-bold ${isAllow ? 'text-teal-700' : 'text-rose-700'}">${r.subnet_cidr}</td>
                <td class="p-3 text-slate-800 font-medium">${r.description}</td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[11px] font-bold ${isAllow ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}">
                        ${r.rule_type}
                    </span>
                </td>
                <td class="p-3">
                    <span class="inline-flex items-center text-emerald-600 font-semibold text-[11px]">
                        <span class="w-2 h-2 rounded-full bg-emerald-500 mr-1.5"></span> Enforced
                    </span>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading firewall rules:", e);
    }
}

async function testArbitraryIp() {
    const ipInput = document.getElementById("customTestIpInput").value.trim();
    const resultBox = document.getElementById("testIpResultBox");

    if (!ipInput) {
        showToast("Please enter an IP address to test", "warning");
        return;
    }

    try {
        const res = await fetch("/api/security/test_ip", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ipInput, role: currentUser ? currentUser.role : "DOCTOR" })
        });
        const data = await res.json();

        resultBox.classList.remove("hidden");
        if (data.allowed) {
            resultBox.className = "p-3 rounded-lg text-xs bg-emerald-50 border border-emerald-200 text-emerald-900";
            resultBox.innerHTML = `
                <div class="font-bold flex items-center"><i class="fa-solid fa-circle-check text-emerald-600 mr-1.5"></i> ALLOWED ACCESS</div>
                <div class="mt-1">${data.reason} (Matched: <code>${data.matched_rule}</code>)</div>
            `;
        } else {
            resultBox.className = "p-3 rounded-lg text-xs bg-rose-50 border border-rose-200 text-rose-900";
            resultBox.innerHTML = `
                <div class="font-bold flex items-center"><i class="fa-solid fa-circle-xmark text-rose-600 mr-1.5"></i> BLOCKED BY FIREWALL</div>
                <div class="mt-1">${data.reason}</div>
            `;
        }
    } catch (err) {
        showToast("Error evaluating IP", "error");
    }
}

// =========================================================================
// AUTOMATED SECURITY TEST SUITE (ASSIGNMENT EVALUATION)
// =========================================================================

async function runAutomatedTests() {
    const btn = document.getElementById("runTestsBtn");
    const container = document.getElementById("testsResultsContainer");
    const banner = document.getElementById("testSummaryBanner");

    if (btn) btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> Running Verification...`;

    try {
        const res = await fetch("/api/security/run_automated_tests", { method: "POST" });
        const data = await res.json();

        container.innerHTML = "";
        banner.classList.remove("hidden");

        const overallIcon = document.getElementById("testOverallIcon");
        const overallTitle = document.getElementById("testOverallTitle");
        const overallSubtitle = document.getElementById("testOverallSubtitle");
        const timestampEl = document.getElementById("testTimestamp");

        if (data.all_passed) {
            overallIcon.className = "w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-lg bg-emerald-600";
            overallIcon.innerHTML = `<i class="fa-solid fa-check"></i>`;
            overallTitle.textContent = "All 6 Automated Security Tests Passed";
            overallSubtitle.textContent = `Security Policy Verification: 100% Compliance (${data.passed_tests} / ${data.total_tests})`;
        } else {
            overallIcon.className = "w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-lg bg-rose-600";
            overallIcon.innerHTML = `<i class="fa-solid fa-xmark"></i>`;
            overallTitle.textContent = "Security Compliance Discrepancy Found";
        }
        timestampEl.textContent = `Executed: ${new Date(data.timestamp).toLocaleTimeString()}`;

        data.results.forEach(t => {
            const card = document.createElement("div");
            card.className = "glass-panel p-4 rounded-xl border border-slate-200 space-y-2";
            card.innerHTML = `
                <div class="flex justify-between items-start">
                    <div>
                        <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-bold">${t.test_id}</span>
                        <h4 class="font-bold text-slate-900 text-xs mt-1">${t.name}</h4>
                    </div>
                    <span class="px-2.5 py-1 rounded text-xs font-bold ${t.passed ? 'bg-emerald-100 text-emerald-800 border border-emerald-300' : 'bg-rose-100 text-rose-800'}">
                        ${t.passed ? 'PASSED' : 'FAILED'}
                    </span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-[11px] bg-slate-50 p-2.5 rounded-lg border border-slate-100 font-mono">
                    <div><span class="text-slate-400">Expected:</span> <strong class="text-slate-700">${t.expected}</strong></div>
                    <div><span class="text-slate-400">Actual:</span> <strong class="text-slate-700">${t.actual}</strong></div>
                </div>
                <div class="text-[11px] text-slate-600">${t.details}</div>
            `;
            container.appendChild(card);
        });

        showToast("Automated security test suite completed!", "success");
    } catch (err) {
        showToast("Failed to run test suite", "error");
    } finally {
        if (btn) btn.innerHTML = `<i class="fa-solid fa-play mr-1.5"></i> Execute Test Suite`;
    }
}

// =========================================================================
// AUDIT LOGS
// =========================================================================

async function loadAuditLogs() {
    try {
        const res = await fetch("/api/audit/logs?limit=40");
        const data = await res.json();
        const logs = data.logs || [];

        const tbody = document.getElementById("auditLogsTableBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        logs.forEach(l => {
            const tr = document.createElement("tr");
            tr.className = "hover:bg-slate-50 transition border-b border-slate-100";
            const isBlocked = l.status === "BLOCKED" || l.status === "DENIED" || l.status === "FAILED";
            tr.innerHTML = `
                <td class="p-3 font-mono text-[11px] text-slate-500">${new Date(l.timestamp).toLocaleTimeString()}</td>
                <td class="p-3 font-semibold text-slate-900">${l.username || 'System'}</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700">${l.role || 'GUEST'}</span></td>
                <td class="p-3 font-mono text-[11px] ${l.client_ip.startsWith('192.168.10') ? 'text-teal-700 font-bold' : 'text-rose-700 font-bold'}">${l.client_ip}</td>
                <td class="p-3 font-mono text-[11px] text-slate-800">${l.action}</td>
                <td class="p-3 text-slate-600 text-[11px]">${l.resource_type}</td>
                <td class="p-3">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isBlocked ? 'bg-rose-100 text-rose-800 border border-rose-300' : 'bg-emerald-100 text-emerald-800'}">
                        ${l.status}
                    </span>
                </td>
                <td class="p-3 text-slate-600 text-[11px] max-w-xs truncate" title="${l.details}">${l.details}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error loading audit logs:", e);
    }
}

// =========================================================================
// UI HELPERS (MODALS & TOASTS)
// =========================================================================

function closeModal(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.classList.add("hidden");
}

function showToast(message, type = "info") {
    const existing = document.getElementById("toastNotification");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "toastNotification";
    let bg = "bg-slate-900 text-white";
    let icon = "fa-circle-info text-blue-400";
    if (type === "success") { bg = "bg-emerald-900 text-white"; icon = "fa-circle-check text-emerald-400"; }
    if (type === "warning") { bg = "bg-amber-900 text-white"; icon = "fa-triangle-exclamation text-amber-400"; }
    if (type === "error") { bg = "bg-rose-900 text-white"; icon = "fa-circle-exclamation text-rose-400"; }

    toast.className = `fixed bottom-6 right-6 z-50 px-4 py-3 rounded-xl shadow-2xl flex items-center space-x-3 text-xs font-medium ${bg} border border-white/10 transition-all duration-300`;
    toast.innerHTML = `<i class="fa-solid ${icon} text-base"></i><span>${message}</span>`;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}
