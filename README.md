# PE Packing Detection Tool

Python script to detect packed Windows PE files using: 
    - Section entropy analysis
    - Suspicious API detection
    - YARA rule matching
    - Packer signature detection
    - Section name analysis

## Requirements

- Python 3+
- pefile
- yara-python
- lief
- argparse
(or can use .venv) 
Dataset taken from: https://github.com/packing-box/dataset-packed-pe
- `packed/` - Directory containing packed samples
- `not-packed/` - Directory containing non-packed samples
- `yara_rules/` - Directory containing YARA rule files
- `db/` - Directory containing JSON databases for section and packer signatures


```bash
python combined_detector.py malware.exe
```

## Credits

### YARA
This project partially  implements YARA for pattern matching and malware detection.  https://github.com/VirusTotal/yara

### RustPacker
https://github.com/Nariod/RustPacker 

### PyPackerDetect -> sections.json / packers.json 
https://github.com/cylance/PyPackerDetect
