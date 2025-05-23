import pefile
import math
import json
import yara
import argparse
import os

# Load databases
def load_databases():
    with open("./db/sections.json", "r", encoding="utf-8") as f:
        known_sections = json.load(f)["sections"]["known"]
    with open("./db/packers.json", "r", encoding="utf-8") as f:
        packer_map = json.load(f)["packers"]
    return known_sections, packer_map

# Tính entropy
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

# Phát hiện packer qua tên section
def detect_packer_name(section_names, packer_map):
    for name in section_names:
        for key, value in packer_map.items():
            if key.lower() in name.lower():
                return value
    return None

# Heuristic check
def is_packed(pe, known_sections, packer_map):
    suspicious_entropy = 7.0
    min_sections = 3
    high_entropy_count = 0
    suspicious_sections = []
    section_names = []

    print(f"[+] Có {len(pe.sections)} section trong file\n")

    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        section_names.append(name)
        entropy = calculate_entropy(section.get_data())
        line = f"    Section {name}: entropy = {entropy}"
        if entropy > suspicious_entropy:
            line += " -> packed"
            high_entropy_count += 1
        print(line)
        if name not in known_sections:
            suspicious_sections.append(name)

    conditions_met = sum([
        high_entropy_count >= 1,
        len(pe.sections) < min_sections,
        len(suspicious_sections) > 0
    ])

    packer_name = detect_packer_name(section_names, packer_map)
    return conditions_met >= 1, packer_name

# Load YARA rules
def load_yara_rules(rule_files):
    try:
        rules_dict = {f"ns{i}": path for i, path in enumerate(rule_files)}
        return yara.compile(filepaths=rules_dict)
    except yara.SyntaxError as e:
        print(f"[!] YARA Syntax Error: {e}")
        return None

# Quét YARA
def yara_scan_file(file_path, rules):
    try:
        matches = rules.match(file_path)
        return [m.rule for m in matches] if matches else []
    except Exception as e:
        print(f"[!] YARA scan error: {e}")
        return []

def check_file(file_path, rules, known_sections, packer_map):
    try:
        pe = pefile.PE(file_path)
        print(f"[+] Đang phân tích file: {file_path}")
        suspicious_entropy = 7.0
        suspicious_sections = []
        high_entropy = False
        section_names = []

        print(f"[+] Có {len(pe.sections)} section trong file\n")

        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            section_names.append(name)
            entropy = calculate_entropy(section.get_data())
            line = f"    Section {name}: entropy = {entropy}"
            if entropy > suspicious_entropy:
                line += " -> high entropy"
                high_entropy = True
            if name not in known_sections:
                suspicious_sections.append(name)
            print(line)

        print("\n[+] HEURISTIC ANALYSIS:")
        if suspicious_sections and not high_entropy:
            print("    🟡 Unknown section(s) found → Low confidence")
        if high_entropy and not suspicious_sections:
            print("    🔶 High entropy detected → Possibly packed")
        if high_entropy and suspicious_sections:
            print("    🔴 High entropy + unknown section → Likely packed")
        if not suspicious_sections and not high_entropy:
            print("    ✅ No anomaly detected in section entropy or names")

        # YARA analysis
        yara_hits = yara_scan_file(file_path, rules)
        packer_related = [r for r in yara_hits if any(x in r.lower() for x in [
            "packer", "packed", "upx", "aspack", "mpress", "rustpacker"
        ])]

        print("\n[+] YARA ANALYSIS:")
        if packer_related:
            print(f"    🔴 Matched packer rule(s): {', '.join(packer_related)} → Packed (high confidence)")
        else:
            print("    🔵 No YARA packer rule matched")

        other_info = set(yara_hits) - set(packer_related)
        if other_info:
            print(f"    ℹ️  YARA (info only): {', '.join(other_info)}")

        # Final verdict
        print("\n→ FINAL VERDICT:")
        if packer_related or (high_entropy and suspicious_sections):
            print("    ✅ PACKED (High confidence)")
        elif high_entropy or suspicious_sections:
            print("    ⚠️  Possibly packed (Low–Medium confidence)")
        else:
            print("    ❎ Not packed")

    except Exception as e:
        print(f"[!] Error processing {file_path}: {e}")


# === MAIN ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect PE packing using YARA + Heuristic")
    parser.add_argument("pe_file", help="Đường dẫn tới file PE cần phân tích")
    parser.add_argument("--rules", nargs='+', default=[
        "yara_rules/peid.yar",
        "yara_rules/packer.yar",
        "yara_rules/packer_compiler_signatures.yar",
        "yara_rules/rustpacker.yar" 
    ], help="Danh sách file .yar rules")
    args = parser.parse_args()

    if not os.path.isfile(args.pe_file):
        print(f"[!] Không tìm thấy file: {args.pe_file}")
        exit(1)

    known_sections, packer_map = load_databases()
    rules = load_yara_rules(args.rules)

    if rules:
        check_file(args.pe_file, rules, known_sections, packer_map)
