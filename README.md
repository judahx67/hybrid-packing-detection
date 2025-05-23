# PE Packing Detection Tool

Python script to detect packed Windows PE files using API calls analysis, section names matching, entropy analysis and yara rulematching. 

## Requirements

- Python 3+
- pefile
- yara-python
- lief
- argparse
Dataset taken from: https://github.com/packing-box/dataset-packed-pe
- `packed/` - Directory containing packed samples
- `not-packed/` - Directory containing non-packed samples
- `yara_rules/` - Directory containing YARA rule files
- `db/` - Directory containing JSON databases for section and packer signatures


```bash
python analyze_files.py
```

## Credits

### YARA
This project partially  implements YARA for pattern matching and malware detection.  https://github.com/VirusTotal/yara

### RustPacker
https://github.com/Nariod/RustPacker 


