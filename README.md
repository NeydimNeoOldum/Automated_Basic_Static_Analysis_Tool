# File Analyzer - Static File Analysis Tool
 
This is a Python-based GUI tool for static analysis of various file types including executables, compressed files, documents, and PDFs. It identifies file types by signature, extracts metadata, checks for password protection, and performs YARA rule matching to detect packed binaries.
 
## Features
 
- Detects real file type based on file signatures, not extensions
- Detects password-protected PDFs, ZIPs, RARs, and 7z files
- Extracts metadata from DOCX, DOC, and PDF files
- Detects VBA Macros and encryption in Office documents
- Analyzes PE metadata (entropy, DLL imports, sections, compilation date)
- Extracts embedded URLs, IPs, and domains from binaries
- Runs YARA rules on PE files to detect packing
- Generates a modern HTML report of findings
- User-friendly `tkinter` GUI interface
## External Python Libraries
 
The following external libraries are required:
 
- `pefile`
- `rarfile`
- `py7zr`
- `PyPDF2`
- `olefile`
- `oletools`
- `python-docx`
- `yara-python`
## Installation
 
Run the provided script below to install all required packages:
 
```bash
pip install pefile rarfile py7zr PyPDF2 olefile oletools python-docx yara-python
```
