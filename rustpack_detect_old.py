# malware_detector.py
# Integrated malware detector with scoring-based heuristic analysis for packing indicators

import lief
import sys
import hashlib

def get_section_hashes(binary):
    """Extracts hashes of sections for heuristic analysis."""
    hashes = {}
    for section in binary.sections:
        if section.size > 0:
            hashes[section.name] = hashlib.sha256(bytes(section.content)).hexdigest()
    return hashes

def score_based_detection(binary_path):
    binary = lief.parse(binary_path)
    if binary is None:
        print("[!] Failed to parse binary.")
        return 0

    # Heuristic: Assign scores for suspicious indicators
    suspicious_apis = {
        "VirtualAlloc": 1, "VirtualAllocEx": 1, "WriteProcessMemory": 2,
        "CreateRemoteThread": 2, "NtCreateThreadEx": 3,
        "NtAllocateVirtualMemory": 2, "AddVectoredExceptionHandler": 1
    }

    imports = set()
    for entry in binary.imports:
        for func in entry.entries:
            imports.add(func.name)

    score = 0
    for api, api_score in suspicious_apis.items():
        if api in imports:
            print(f"[+] Detected API: {api} (+{api_score})")
            score += api_score

    return score

def main():
    if len(sys.argv) != 2:
        print("Usage: python malware_detector.py <binary>")
        sys.exit(1)

    binary_path = sys.argv[1]
    print("[*] Analyzing binary:", binary_path)

    score = score_based_detection(binary_path)
    print(f"[*] Detection score: {score}")

    if score >= 5:
        print("[!] High suspicion: Binary is likely packed or malicious.")
    elif score >= 3:
        print("[~] Medium suspicion: Binary may be packed or use suspicious techniques.")
    else:
        print("[-] Low suspicion: No strong packing indicators detected.")

if __name__ == "__main__":
    main()