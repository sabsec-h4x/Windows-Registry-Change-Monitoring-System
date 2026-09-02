import os
import re
import math
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

def extract_file_path_from_command(command_line: str) -> Optional[str]:
    """Extracts a valid file path from a command line string with arguments."""
    if not isinstance(command_line, str) or not command_line.strip():
        return None

    clean = command_line.strip()

    # 1. Check for quoted path e.g. "C:\Program Files\app.exe" --arg
    quoted_match = re.match(r'^"([^"]+)"', clean)
    if quoted_match:
        cand = quoted_match.group(1)
        if os.path.exists(cand):
            return cand

    # 2. Check for standard Windows path
    path_match = re.match(r'^([a-zA-Z]:\\[^\s]+\.(exe|dll|bat|cmd|vbs|ps1|sys|scr))', clean, re.IGNORECASE)
    if path_match:
        cand = path_match.group(1)
        if os.path.exists(cand):
            return cand

    # 3. Space-split progressive matching (for unquoted paths with spaces)
    parts = clean.split()
    for i in range(len(parts), 0, -1):
        cand = " ".join(parts[:i]).strip('"\'')
        if os.path.exists(cand) and not os.path.isdir(cand):
            return cand

    # 4. Check system environment variables expansion
    expanded = os.path.expandvars(clean)
    if expanded != clean:
        return extract_file_path_from_command(expanded)

    return None

def compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Computes SHA-256 and MD5 hashes for a target file."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                md5.update(chunk)
        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest()
        }
    except Exception:
        return {"sha256": "ERROR_READING_FILE", "md5": "ERROR_READING_FILE"}

def compute_entropy(data: bytes) -> float:
    """Calculates Shannon entropy for byte buffer."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)

def check_authenticode_signature(file_path: str) -> Dict[str, Any]:
    """
    Verifies Authenticode digital signature using PowerShell Get-AuthenticodeSignature.
    Returns status: Valid, NotSigned, HashMismatch, UnknownError, etc.
    """
    try:
        cmd = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"(Get-AuthenticodeSignature -LiteralPath '{file_path}') | Select-Object Status, SignerCertificate | ConvertTo-Json -Compress\""
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout.strip():
            import json
            sig_info = json.loads(proc.stdout.strip())
            status_code = sig_info.get("Status")
            # Convert status code/name to readable string
            # 0=Valid, 1=UnknownError, 2=NotSigned, 3=HashMismatch, 4=NotSupportedFileFormat, 5=Incompatible
            status_map = {0: "Valid", 1: "UnknownError", 2: "NotSigned", 3: "HashMismatch", 4: "NotSupportedFileFormat"}
            readable_status = status_map.get(status_code, str(status_code))
            cert = sig_info.get("SignerCertificate")
            subject = cert.get("Subject", "") if isinstance(cert, dict) else ""
            issuer = cert.get("Issuer", "") if isinstance(cert, dict) else ""
            is_signed = readable_status in ["Valid", "0", 0]

            return {
                "is_signed": is_signed,
                "status": readable_status,
                "signer_subject": subject,
                "signer_issuer": issuer
            }
    except Exception as e:
        return {"is_signed": False, "status": f"CheckFailed: {str(e)}", "signer_subject": "", "signer_issuer": ""}

    return {"is_signed": False, "status": "NotSigned", "signer_subject": "", "signer_issuer": ""}

def analyze_pe_file(file_path: str) -> Dict[str, Any]:
    """
    Comprehensive static forensic analysis of a persistence executable/DLL.
    """
    if not os.path.exists(file_path):
        return {"exists": False, "file_path": file_path}

    try:
        stat = os.stat(file_path)
        file_size = stat.st_size
        created_time = datetime.fromtimestamp(stat.st_ctime).isoformat()
        modified_time = datetime.fromtimestamp(stat.st_mtime).isoformat()
    except Exception:
        file_size = 0
        created_time = ""
        modified_time = ""

    hashes = compute_file_hashes(file_path)
    sig_info = check_authenticode_signature(file_path)

    pe_metadata: Dict[str, Any] = {
        "exists": True,
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "file_size_bytes": file_size,
        "created_at": created_time,
        "modified_at": modified_time,
        "hashes": hashes,
        "signature": sig_info,
        "is_pe": False,
        "sections": [],
        "overall_entropy": 0.0,
        "is_high_entropy": False
    }

    # Calculate overall file entropy
    try:
        with open(file_path, "rb") as f:
            sample = f.read(min(file_size, 1024 * 1024))
            pe_metadata["overall_entropy"] = compute_entropy(sample)
            pe_metadata["is_high_entropy"] = pe_metadata["overall_entropy"] > 7.0
    except Exception:
        pass

    # Extract PE header structures if pefile is present
    if PEFILE_AVAILABLE:
        try:
            pe = pefile.PE(file_path)
            pe_metadata["is_pe"] = True
            pe_metadata["machine"] = hex(pe.FILE_HEADER.Machine)
            pe_metadata["compile_timestamp"] = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
            pe_metadata["is_dll"] = pe.is_dll()
            pe_metadata["is_exe"] = pe.is_exe()

            sections_info = []
            for sec in pe.sections:
                sec_name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
                sec_entropy = sec.get_entropy()
                sections_info.append({
                    "name": sec_name,
                    "virtual_size": sec.Misc_VirtualSize,
                    "entropy": round(sec_entropy, 3)
                })
            pe_metadata["sections"] = sections_info
            pe.close()
        except Exception:
            pass

    return pe_metadata
