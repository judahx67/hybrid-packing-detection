import pefile
import math
import json
import yara
import argparse
import os
import lief
import hashlib
from datetime import datetime

def log_debug(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

# Load db
def load_databases():
    with open("./db/sections.json", "r", encoding="utf-8") as f:
        known_sections = json.load(f)["sections"]["known"]
    with open("./db/packers.json", "r", encoding="utf-8") as f:
        packer_map = json.load(f)["packers"]
    return known_sections, packer_map

# Calculate entropy
def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)

# Detect packer by section names
# def detect_packer_name(section_names, packer_map):
#     for name in section_names:
#         for key, value in packer_map.items():
#             if key.lower() in name.lower():
#                 return value
#     return None


def detect_packer_name(section_names, packer_map):
    matches = []
    for name in section_names:
        for key, value in packer_map.items():
            if key.lower() in name.lower():
                matches.append(value)
    return list(set(matches)) if matches else None


# Anomaly score for API calls
def score_based_detection(binary):
    suspicious_apis = {
        "VirtualAlloc": 3,
        "VirtualProtect": 4,
        "VirtualAllocEx": 3,
        "WriteProcessMemory": 5,
        "CreateRemoteThread": 7,
        "NtCreateThreadEx": 7,
        "ZwUnmapViewOfSection": 6,
        "LoadLibrary": 2,
        "GetProcAddress": 2,
        "NtAllocateVirtualMemory": 3,
        "AddVectoredExceptionHandler": 2,
        "SetWindowsHookEx": 2,
        "QueueUserAPC": 3
    }

    imports = set()
    for entry in binary.imports:
        for func in entry.entries:
            imports.add(func.name)

    score = 0
    detected_apis = []
    sequence_detected = False

    # Check unpacking sequence
    if all(api in imports for api in ["VirtualAlloc", "WriteProcessMemory", "CreateThread"]):
        score += 10  # Reduced from 15
        detected_apis.append("Classic unpacking sequence detected (+10)")
        sequence_detected = True

    # Check for individual APIs
    for api, api_score in suspicious_apis.items():
        if api in imports:
            detected_apis.append(f"{api} (+{api_score})")
            score += api_score

    # Check for frequency calls
    suspicious_count = len([api for api in imports if api in suspicious_apis])
    if suspicious_count >= 6:  # Increased threshold from 5 to 6
        score += 7  # Reduced from 10
        detected_apis.append(f"High frequency of suspicious calls detected (+7)")

    return score, detected_apis

# Load YARA rules
def load_yara_rules(rule_files):
    try:
        rules_dict = {f"ns{i}": path for i, path in enumerate(rule_files)}
        return yara.compile(filepaths=rules_dict)
    except yara.SyntaxError as e:
        print(f"[!] YARA Syntax Error: {e}")
        return None

# YARA scan
def yara_scan_file(file_path, rules):
    try:
        matches = rules.match(file_path)
        return [m.rule for m in matches] if matches else []
    except Exception as e:
        print(f"[!] YARA scan error: {e}")
        return []

def analyze_file(file_path, rules, known_sections, packer_map):
    try:
        log_debug(f"Analyzing file: {file_path}")
        
        # Initialize variables
        is_packed = False
        confidence = "Low"
        
        # Load PE
        pe = pefile.PE(file_path)
        binary = lief.parse(file_path)
        
        if binary is None:
            log_debug("Failed to parse binary with LIEF", "ERROR")
            return
        
        # Section
        log_debug("Section Analysis", "INFO")
        log_debug(f"Found {len(pe.sections)} sections")
        
        suspicious_entropy = 7.0
        high_entropy_count = 0
        suspicious_sections = []
        section_names = []
        
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            section_names.append(name)
            entropy = calculate_entropy(section.get_data())
            if entropy > suspicious_entropy:
                high_entropy_count += 1
                log_debug(f"Section {name}: entropy = {entropy} (HIGH)", "WARNING")
            else:
                log_debug(f"Section {name}: entropy = {entropy}")
            if name not in known_sections:
                suspicious_sections.append(name)
        
        # Calculate total file entropy
        total_data = bytearray()
        for section in pe.sections:
            total_data.extend(section.get_data())
        total_entropy = calculate_entropy(total_data)
        log_debug(f"Total file entropy: {total_entropy}")
        if total_entropy > suspicious_entropy:
            log_debug("High total file entropy detected", "WARNING")

        # API Analysis
        log_debug("API Analysis", "INFO")
        api_score, detected_apis = score_based_detection(binary)
        if detected_apis:
            log_debug("Detected suspicious APIs:", "WARNING")
            for api in detected_apis:
                log_debug(f"    {api}", "WARNING")
        log_debug(f"Total API score: {api_score}")

        # YARA Analysis
        log_debug("YARA Analysis", "INFO")
        yara_hits = yara_scan_file(file_path, rules)
        packer_related = [r for r in yara_hits if any(x in r.lower() for x in [
            "packer", "packed", "upx", "aspack", "mpress"
        ])]

        if packer_related:
            log_debug(f"Matched packer rule(s): {', '.join(packer_related)}", "WARNING")
        else:
            log_debug("No packer rules matched")

        other_info = set(yara_hits) - set(packer_related)
        if other_info:
            log_debug(f"Other matches: {', '.join(other_info)}")

        # Check for known packer signatures
        packer_name = detect_packer_name(section_names, packer_map)
        if packer_name:
            log_debug(f"Detected packer: {packer_name}", "WARNING")
            is_packed = True 
            confidence = "High"
        
        elif packer_related:
            is_packed = True
            confidence = "High"
        elif high_entropy_count >= 2 and suspicious_sections:
            is_packed = True
            confidence = "High"
        elif api_score >= 10:
            is_packed = True
            confidence = "High"
        elif sum([high_entropy_count >= 2, bool(suspicious_sections), api_score >= 7]) >= 2:
            is_packed = True
            confidence = "Medium"
        elif suspicious_sections or high_entropy_count >= 2 or api_score > 7:
            is_packed = True
            confidence = "LOW"
        
        # Print final verdict
        log_debug("Final Verdict", "INFO")
        if is_packed:
            log_debug(f"PACKED ({confidence} confidence)", "WARNING")
            if confidence == "High":
                log_debug("Multiple indicators detected", "WARNING")
            elif confidence == "Medium":
                log_debug("Some suspicious indicators found", "WARNING")
        else:
            log_debug("NOT PACKED")
            if confidence == "Medium":
                log_debug("Some suspicious indicators found", "WARNING")
            else:
                log_debug("No suspicious indicators detected")

    except Exception as e:
        log_debug(f"Error processing {file_path}: {e}", "ERROR")

def main():
    parser = argparse.ArgumentParser(description="Combined PE Packing Detector")
    parser.add_argument("pe_file", help="Path to PE file to analyze")
    parser.add_argument("--rules", nargs='+', default=[
        "yara_rules/peid.yar",
        "yara_rules/packer.yar",
        "yara_rules/packer_compiler_signatures.yar"
    ], help="List of YARA rule files")
    args = parser.parse_args()

    if not os.path.isfile(args.pe_file):
        print(f"[!] File not found: {args.pe_file}")
        exit(1)

    known_sections, packer_map = load_databases()
    rules = load_yara_rules(args.rules)

    if rules:
        analyze_file(args.pe_file, rules, known_sections, packer_map)

if __name__ == "__main__":
    main() 