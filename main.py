import os
import zipfile
import rarfile
import py7zr
import pefile #for parsing and analyzing PE (Portable Executable) files
import re #pattern recognition
from PyPDF2 import PdfReader
import olefile #safely read older binary Office formats
from oletools.olevba import VBA_Parser # Detecting and extracting VBA macros
from docx import Document
from urllib.parse import urlparse
import datetime
import yara
import tkinter as tk
from tkinter import filedialog, messagebox
import webbrowser

FILE_SIGNATURES = {
    b'%PDF-': 'pdf',
    b'\x7fELF': 'elf',
    b'MZ': 'exe or dll',                           # Windows PE (exe, dll, scr)
    b'PK\x03\x04': 'zip/docx/xlsx/pptx/jar/apk',  # ZIP and Open XML
    b'Rar!\x1A\x07\x00': 'rar',                    # RAR4
    b'Rar!\x1A\x07\x01\x00': 'rar',               # RAR5
    b'7z\xBC\xAF\x27\x1C': '7z',
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': 'ole',  # OLE compound – sub-typed later
    b'\xFF\xD8\xFF': 'jpg',
    b'\x89PNG': 'png',
    b'GIF89a': 'gif',
    b'GIF87a': 'gif',
    b'BM': 'bmp',
    b'CWS': 'swf',   # Compressed Flash SWF
    b'FWS': 'swf',   # Uncompressed Flash SWF
    b'ZWS': 'swf',   # LZMA Flash SWF
    b'\x4C\x00\x00\x00\x01\x14\x02\x00': 'lnk',  # Windows shortcut
    b'\x1F\x8B': 'gz',
    b'BZh': 'bz2',
    b'\xCA\xFE\xBA\xBE': 'class',  # Java .class
    b'ITSF': 'chm',                 # Compiled HTML Help
    b'MSCF': 'cab',                 # Microsoft Cabinet
    b'SQLite format 3\x00': 'db',  # SQLite database
    b'RIFF': 'wav or avi',          # sub-typed by detectRiffSubtype
    b'<!DOCTYP': 'html',
    b'<html': 'html',
    b'<HTML': 'html',
    b'<?xml': 'xml/sct/wsf',        # XML-based – sub-typed later
    b'<svg': 'svg',
    b'{\\rtf': 'rtf',
    # EML-specific headers come BEFORE MIME-Version to catch plain emails
    b'Return-Path:': 'eml',
    b'Received: ': 'eml',
    b'Delivered-To:': 'eml',
    b'MIME-Version:': 'mime',       # sub-typed to mhtml or eml
    # Registry files
    b'REGEDIT4': 'reg',
    b'Windows Registry Editor': 'reg',
    b'ID3': 'mp3',
    b'\xFF\xFB': 'mp3',
    b'\xFF\xF3': 'mp3',
    b'\xFF\xF2': 'mp3',
    b'fLaC': 'flac',
    b'OggS': 'ogg',
    b'\x00\x00\x00\x14ftyp': 'mp4/mov',  # ftyp box size 20 – sub-typed
    b'\x00\x00\x00\x18ftyp': 'mp4/mov',  # ftyp box size 24 – sub-typed
    b'\x00\x00\x00\x1Cftyp': 'mp4/mov',  # ftyp box size 28 – sub-typed
    b'\x00\x00\x00 ftyp': 'mp4/mov',     # ftyp box size 32 – sub-typed
    b'MThd': 'midi',
    b'\x25\x21PS-Adobe': 'ps/eps',
}

def generate_html_report(html_carts, output_file="report.html"):
    html_top = """
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>File Analysis Report</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        :root{--bg:#0d1117;--card:#161b22;--text:#c9d1d9;--accent:#3fb950;--danger:#f85149;--muted:#8b949e;}
        *{box-sizing:border-box;margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;}
        body{background:var(--bg);color:var(--text);padding:2rem;}
        h1{font-size:1.8rem;margin-bottom:1rem;color:var(--accent);}
        .card{background:var(--card);border:1px solid #30363d;border-radius:8px;padding:1.5rem;margin-bottom:2rem;box-shadow:0 4px 12px rgba(0,0,0,.25);}
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:1rem;}
        .label{font-weight:600;color:var(--muted);}
        .value{font-size:1.1rem;}
        .badge{display:inline-block;padding:.2rem .6rem;border-radius:999px;font-size:.75rem;font-weight:600;margin-right:.4rem;}
        .badge.good{background:rgba(63,185,80,.2);color:var(--accent);}
        .badge.neutral{background:rgba(139,148,158,.15);color:var(--muted);}
        .button{display:inline-block;background:var(--accent);color:#fff;padding:.8rem 1.6rem;border:none;border-radius:6px;font-size:1rem;font-weight:600;text-decoration:none;transition:background .2s ease-in-out;}
        .button:hover{background:#2ea043;}
        footer{margin-top:3rem;font-size:.8rem;color:var(--muted);text-align:center;}
        @media(max-width:600px){.grid{grid-template-columns:1fr;}}
      </style>
    </head>
    <body>
      <h1>File Report</h1>
    """
    html_footer = """
      <a href="https://www.youtube.com/watch?v=xvFZjo5PgG0" class="button" target="_blank" rel="noopener">
        Click For More Info
      </a>
      <footer>
        This page is for you<br>
        Designed by Emir Avci
      </footer>
    </body>
    </html>
    """

    final_html = html_top + html_carts + html_footer
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(final_html)

    webbrowser.open(output_file)

def inspectZip(file_path):
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            entries = z.namelist()
            # Normalise separators so backslash variants still match
            norm = [e.replace('\\', '/') for e in entries]
            if '[Content_Types].xml' in norm:
                has_vba = any('vbaProject.bin' in e for e in norm)
                if any(e.startswith('word/') for e in norm):
                    return 'docm' if has_vba else 'docx'
                elif any(e.startswith('xl/') for e in norm):
                    return 'xlsm' if has_vba else 'xlsx'
                elif any(e.startswith('ppt/') for e in norm):
                    try:
                        ct = z.read('[Content_Types].xml').decode('utf-8', errors='ignore')
                        if 'slideshow.main' in ct:
                            return 'ppsx'
                    except Exception:
                        pass
                    return 'pptx'
            elif 'AndroidManifest.xml' in norm:
                return 'apk'
            elif 'META-INF/MANIFEST.MF' in norm:
                return 'jar'
            return 'zip'
    except Exception:
        return 'zip'

def detectDllbyExport(file_path):
    pe = pefile.PE(file_path)
    # IMAGE_FILE_DLL flag (0x2000) is the reliable way to distinguish DLL from EXE
    if pe.FILE_HEADER.Characteristics & 0x2000:
        return "dll"
    return "exe"

def detectOleSubtype(file_path):
    """Identify specific OLE compound document type (doc, xls, ppt, pub)."""
    if not olefile.isOleFile(file_path):
        return 'ole'
    try:
        ole = olefile.OleFileIO(file_path)
        if ole.exists('WordDocument'):
            subtype = 'doc'
        elif ole.exists('Workbook') or ole.exists('Book'):
            subtype = 'xls'
        elif ole.exists('PowerPoint Document'):
            subtype = 'ppt'
        elif ole.exists('Quill'):
            subtype = 'pub'
        elif ole.exists('_Tables') or ole.exists('_StringData'):
            # MSI-specific OLE streams (Windows Installer package)
            subtype = 'msi'
        elif ole.exists('EncryptedPackage'):
            # Password-encrypted Office document — real type hidden inside ciphertext
            # Use the file extension as the only available hint
            ext = os.path.splitext(file_path)[1].lower().lstrip('.')
            office_map = {
                'docx': 'encrypted-docx', 'docm': 'encrypted-docm', 'doc': 'encrypted-doc',
                'xlsx': 'encrypted-xlsx', 'xlsm': 'encrypted-xlsm', 'xls': 'encrypted-xls',
                'pptx': 'encrypted-pptx', 'ppsx': 'encrypted-ppsx', 'ppt': 'encrypted-ppt',
            }
            subtype = office_map.get(ext, 'encrypted-office')
        else:
            subtype = 'ole'
        ole.close()
        return subtype
    except Exception:
        return 'ole'

def detectRiffSubtype(file_path):
    """Distinguish WAV from AVI by reading the RIFF form-type field at offset 8."""
    try:
        with open(file_path, 'rb') as f:
            f.seek(8)
            form_type = f.read(4)
        if form_type == b'WAVE':
            return 'wav'
        if form_type == b'AVI ':
            return 'avi'
    except Exception:
        pass
    return 'wav'

def detectIso(file_path):
    """Check for ISO 9660 by reading the primary volume descriptor at offset 32769."""
    try:
        with open(file_path, 'rb') as f:
            f.seek(32769)
            return f.read(5) == b'CD001'
    except Exception:
        return False

def detectTar(file_path):
    """Check for TAR archive using POSIX ustar magic at offset 257."""
    try:
        with open(file_path, 'rb') as f:
            f.seek(257)
            return f.read(5) == b'ustar'
    except Exception:
        return False

def detectXmlSubtype(file_path):
    """Distinguish SCT / WSF from generic XML by checking tag content."""
    try:
        with open(file_path, 'rb') as f:
            content = f.read(2048).decode('utf-8', errors='ignore').lower()
        if '<scriptlet' in content or ('<registration' in content and 'description' in content):
            return 'sct'
        if '<job' in content or ('<script' in content and 'language=' in content):
            return 'wsf'
    except Exception:
        pass
    return 'xml'

def detectMimeSubtype(file_path):
    """Distinguish MHTML from EML when both start with MIME-Version header."""
    try:
        with open(file_path, 'rb') as f:
            content = f.read(1024).decode('utf-8', errors='ignore')
        if 'multipart/related' in content or 'Content-Location:' in content:
            return 'mhtml'
        if any(h in content for h in ('Subject:', 'To:', 'From:', 'Message-ID:')):
            return 'eml'
    except Exception:
        pass
    return 'mhtml'

def detectFtypSubtype(file_path):
    """Read the ftyp brand at offset 8 to distinguish MOV from MP4."""
    try:
        with open(file_path, 'rb') as f:
            f.seek(8)
            brand = f.read(4)
        if brand == b'qt  ':
            return 'mov'
    except Exception:
        pass
    return 'mp4'

def detectScriptType(file_path):
    """Content-based detection for text/script files that have no binary magic."""
    try:
        with open(file_path, 'rb') as f:
            raw = f.read(1024)
        text = raw.decode('utf-8', errors='ignore')
        lower = text.lower().strip()

        if lower.startswith('<?php') or '\n<?php' in lower:
            return 'php'

        if text.startswith('#!'):
            shebang = text.split('\n')[0]
            if 'python' in shebang:
                return 'py'
            if 'ruby' in shebang:
                return 'rb'
            if 'node' in shebang:
                return 'js'
            if 'bash' in shebang or '/sh' in shebang:
                return 'sh'

        # Registry export files
        if lower.startswith('regedit4') or lower.startswith('windows registry editor'):
            return 'reg'

        # WSH settings file – INI-style with [General] or [Script] sections
        if ('[general]' in lower or '[script]' in lower) and ('scriptfile=' in lower or 'command=' in lower):
            return 'wsh'

        bat_hits = sum([
            '@echo' in lower,
            'rem ' in lower,
            'goto ' in lower,
            'setlocal' in lower,
            '%~dp0' in lower,
            'if exist' in lower,
        ])
        if bat_hits >= 2:
            return 'bat'

        ps1_hits = sum([
            'param(' in lower,
            'write-host' in lower,
            'get-childitem' in lower,
            'new-object' in lower,
            'invoke-' in lower,
            '[system.' in lower,
        ])
        if ps1_hits >= 2:
            return 'ps1'

        vbs_hits = sum([
            'wscript' in lower,
            'createobject' in lower,
            'end sub' in lower,
            'end function' in lower,
            'on error resume next' in lower,
            'option explicit' in lower,
        ])
        if vbs_hits >= 2:
            return 'vbs'

        # Visual Basic source (not VBScript – uses Module/Imports/Namespace)
        vb_hits = sum([
            'imports ' in lower,
            'module ' in lower,
            'namespace ' in lower,
            'public sub ' in lower or 'private sub ' in lower,
            'public function ' in lower or 'private function ' in lower,
            'dim ' in lower and ' as ' in lower,
        ])
        if vb_hits >= 2:
            return 'vb'

        # Python without shebang
        py_hits = sum([
            bool(re.search(r'\bimport\s+\w+', text)),
            bool(re.search(r'\bdef\s+\w+\s*\(', text)),
            bool(re.search(r'\bif\s+__name__\s*==', text)),
            'print(' in text,
            bool(re.search(r'\bfrom\s+\w+\s+import\b', text)),
            'self.' in text,
        ])
        if py_hits >= 2:
            return 'py'

        # Java source
        java_hits = sum([
            bool(re.search(r'\bpublic\s+class\s+\w+', text)),
            bool(re.search(r'\bimport\s+java\.', text)),
            bool(re.search(r'\bpublic\s+static\s+void\s+main\b', text)),
            bool(re.search(r'\bpackage\s+[\w.]+;', text)),
            'System.out' in text,
        ])
        if java_hits >= 2:
            return 'java'

        # SQL
        sql_hits = sum([
            bool(re.search(r'\bselect\b', lower)),
            bool(re.search(r'\binsert\s+into\b', lower)),
            bool(re.search(r'\bcreate\s+table\b', lower)),
            bool(re.search(r'\bdrop\s+table\b', lower)),
            bool(re.search(r'\bupdate\s+\w+\s+set\b', lower)),
            bool(re.search(r'\bwhere\s+\w+', lower)),
        ])
        if sql_hits >= 2:
            return 'sql'

        # EML without MIME-Version header (plain RFC 822 format)
        eml_hits = sum([
            bool(re.search(r'^From:\s', text, re.MULTILINE)),
            bool(re.search(r'^To:\s', text, re.MULTILINE)),
            bool(re.search(r'^Subject:\s', text, re.MULTILINE)),
            bool(re.search(r'^Message-ID:\s', text, re.MULTILINE)),
            bool(re.search(r'^Date:\s', text, re.MULTILINE)),
        ])
        if eml_hits >= 3:
            return 'eml'

        js_hits = sum([
            'function(' in lower or 'function (' in lower,
            'var ' in lower or 'let ' in lower or 'const ' in lower,
            'document.' in lower,
            'require(' in lower,
            '=>' in text,
        ])
        if js_hits >= 2:
            return 'js'

        # Plain-text fallback — no null bytes and valid UTF-8 encoding
        with open(file_path, 'rb') as f:
            sample = f.read(8192)
        if b'\x00' not in sample:
            try:
                sample.decode('utf-8')
                return 'txt'
            except UnicodeDecodeError:
                pass

    except Exception:
        pass
    return None

def detectFileType(file_path, max_bytes=20):
    try:
        with open(file_path, 'rb') as f:
            file_head = f.read(max_bytes)
        for sig, filetype in FILE_SIGNATURES.items():
            if file_head.startswith(sig):
                if filetype == 'zip/docx/xlsx/pptx/jar/apk':
                    return inspectZip(file_path)
                if filetype == 'exe or dll':
                    return detectDllbyExport(file_path)
                if filetype == 'ole':
                    return detectOleSubtype(file_path)
                if filetype == 'wav or avi':
                    return detectRiffSubtype(file_path)
                if filetype == 'xml/sct/wsf':
                    return detectXmlSubtype(file_path)
                if filetype == 'mime':
                    return detectMimeSubtype(file_path)
                if filetype == 'mp4/mov':
                    return detectFtypSubtype(file_path)
                return filetype

        # Offset-based checks (cannot use startswith on the header)
        if detectIso(file_path):
            return 'iso'
        if detectTar(file_path):
            return 'tar'

        # Content-based detection for script/text files
        script_type = detectScriptType(file_path)
        if script_type:
            return script_type

        return "unknown"
    except Exception as e:
        return f"Error reading file: {e}"

def compressedFilesPassword(file_path, fileType): #PART 2
    if fileType == 'zip':
        with zipfile.ZipFile(file_path, 'r') as z:
            return any(zinfo.flag_bits & 0x1 for zinfo in z.infolist())
    elif fileType == 'rar':
        with rarfile.RarFile(file_path) as rf:
            return any(f.needs_password() for f in rf.infolist())
    elif fileType == '7z':
        try:
            with py7zr.SevenZipFile(file_path, mode='r') as archive:
                archive.getnames()
            return False
        except py7zr.exceptions.PasswordRequired:
            return True
        except Exception:
            return True
    elif fileType in ('gz', 'bz2', 'tar'):
        return False  # these formats do not support native password protection
    return False

def PdfProtected(file_path):
    reader=PdfReader(file_path)
    if reader.is_encrypted:
        return True
    else:
        return False

def pdfProcess(file_path):
    reader = PdfReader(file_path)
    content=""
    for page in reader.pages:
        content += page.extract_text() or ""
    urls = re.findall(r'https?://[^\s"]+', content)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+(com|org|net|info|biz|ru|io|edu|gov)\b', content)
    elements=[urls,ips, domains]
    return elements

def docOck(file_path, fileType):
    result = {}

    if fileType == "docx":
        with zipfile.ZipFile(file_path, 'r') as docx:
            if 'word/document.xml' not in docx.namelist():
                result['password_protected'] = True
            else:
                result['password_protected'] = False
        doc = Document(file_path)
        result['language'] = doc.core_properties.language or "Unknown"
        result['page_count_estimate'] = len(doc.paragraphs) // 8

    elif fileType in ("doc", "docm"):
        result['language'] = "N/A"
        result['page_count_estimate'] = "N/A"
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            result['encrypted'] = ole.exists('EncryptedPackage')
            result['password_protected'] = ole.exists('EncryptedSummary')
            ole.close()
        else:
            result['encrypted'] = False
            result['password_protected'] = False

    # Guarantee all keys exist so HTML generation never raises KeyError
    result.setdefault('language', 'N/A')
    result.setdefault('page_count_estimate', 'N/A')
    result.setdefault('encrypted', 'N/A')
    result.setdefault('password_protected', False)

    vba = VBA_Parser(file_path)
    result['macros_found'] = vba.detect_vba_macros()
    vba.close()

    if fileType == "docx" and result['macros_found']:
        result['file_type'] = 'docm'

    return result

_VALID_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
    'io', 'co', 'app', 'dev', 'ai', 'cloud',
    'info', 'biz', 'name', 'mobi', 'xyz', 'online', 'site', 'tech',
    'me', 'tv', 'cc', 'ly', 'to', 'onion',
    'uk', 'us', 'de', 'fr', 'ru', 'cn', 'jp', 'br', 'au', 'ca',
    'eu', 'in', 'it', 'es', 'nl', 'pl', 'se', 'ch', 'at', 'be',
    'nz', 'za', 'sg', 'hk', 'tw', 'kr', 'ar', 'mx', 'cl', 'pe',
    'pw', 'tk', 'top', 'bid', 'win', 'su', 'cx',
}

def _url_has_valid_tld(url):
    """Return True only if the URL's domain ends with a recognised TLD."""
    try:
        host = urlparse(url).netloc.split(':')[0].lower()
        if not host or '.' not in host:
            return False
        tld = host.rsplit('.', 1)[-1]
        return tld in _VALID_TLDS and len(url) >= 14
    except Exception:
        return False

def extractStrings(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Extract printable ASCII strings of length 4+
    raw_strings = re.findall(rb"[ -~]{4,}", data)
    decoded_strings = []
    for s in raw_strings:
        try:
            decoded = s.decode()
            if 'PADDING' in decoded or decoded.lower().startswith('truep'):
                continue
            decoded_strings.append(decoded)
        except UnicodeDecodeError:
            continue

    # Extract all URLs from every string (findall catches multiple per line)
    raw_urls = []
    for s in decoded_strings:
        found = re.findall(r'(https?://[^\s"\'<>]+)', s)
        for url in found:
            url = url.rstrip('.,;:<>\\\"\'')
            raw_urls.append(url)

    # Keep only URLs whose domain ends with a known TLD
    urls = list({u for u in raw_urls if _url_has_valid_tld(u)})

    # Extract IP addresses (strict IPv4 match only)
    ips = [s for s in decoded_strings if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s)]

    # Extract domains from the validated URLs
    domain_set = set()
    for url in urls:
        try:
            domain = urlparse(url).netloc.split(':')[0].lower()
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-z]{2,}$', domain):
                domain_set.add(domain)
        except Exception:
            continue

    return {
        'urls': urls,
        'ip_addresses': list(set(ips)),
        'domains': list(domain_set)
    }

def extractMetadata(file_path):
    try:
        pe = pefile.PE(file_path)
        metadata = {}

        # Architecture
        arch_map = {0x014C: 'x86', 0x8664: 'x64'}
        metadata['architecture'] = arch_map.get(pe.FILE_HEADER.Machine, 'Unknown')

        # General entropy
        entropies = [s.get_entropy() for s in pe.sections]
        metadata['general_entropy'] = round(sum(entropies) / len(entropies), 3)

        # File size
        metadata['file_size'] = os.path.getsize(file_path)

        # Section details
        metadata['section_count'] = len(pe.sections)
        metadata['sections'] = []
        for section in pe.sections:
            metadata['sections'].append({
                'name': section.Name.decode(errors='ignore').strip('\x00'),
                'entropy': round(section.get_entropy(), 3),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData
            })

        #  Compilation date
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_date = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        metadata['compile_date'] = compile_date

        #  DLL imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            metadata['imported_dlls'] = [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
        else:
            metadata['imported_dlls'] = []

        return metadata

    except pefile.PEFormatError as e:
        return {'error': f'PE Format Error: {str(e)}'}


def yaraRules(file_path):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        r"C:\compressionDetect.yar",
        os.path.join(script_dir, "compressionDetect.yar"),
        "compressionDetect.yar",
    ]
    yara_path = next((p for p in candidates if os.path.exists(p)), None)
    if not yara_path:
        return "YARA Error: compressionDetect.yar not found"
    try:
        rules = yara.compile(filepath=yara_path)
        matches = rules.match(os.path.abspath(file_path))
        if matches:
            return f"Packed: {' '.join([match.rule for match in matches])}"
        return "Not packed (no YARA match)"
    except Exception as e:
        return f"YARA Error: {str(e)}"


file_list = []

def add_file():
    paths = filedialog.askopenfilenames()
    for file_path in paths:
        if file_path not in file_list:
            file_list.append(file_path)
            listbox.insert(tk.END, file_path)

def analyze_all_files():
    if not file_list:
        messagebox.showwarning("No files", "Please add at least one file.")
        return
    html_cards = ""
    for file_path in file_list:
        file_name=os.path.basename(file_path)
        fileType= detectFileType(file_path)
        if fileType in ['rar', 'zip', '7z', 'gz', 'bz2', 'tar']:
            passwordExist = compressedFilesPassword(file_path,fileType)
            html_cards += f"""
            <div class="card">
            <p class="label">File Name:</p>
            <p class="value" style="word-break:break-all;">{file_name}</p>
            <div class="grid">
                <div>
                <p class="label">File Type:</p>
                <p class="value">{fileType}</p>
                </div>
                <div>
                <p class="label">Password Exist:</p>
                <p class="value">{"Password Protected" if passwordExist else "Non-exist"}</p>
                </div>
            </div>
            </div>
            """

        elif fileType == 'pdf':

            passwordExist= PdfProtected(file_path)
            if passwordExist:
                html_cards += f"""
                <div class="card">
                <p class="label">File Name:</p>
                <p class="value" style="word-break:break-all;">{file_name}</p>
                <div class="grid">
                    <div>
                    <p class="label">File Type:</p>
                    <p class="value">{fileType}</p>
                    </div>
                    <div>
                    <p class="label">Password Exist:</p>
                    <p class="value">Password Protected</p>
                    </div>
                    <div>
                    <p class="label">Urls:</p>
                    <p class="value">Unknown (file is encrypted)</p>
                    </div>
                    <div>
                    <p class="label">IPs:</p>
                    <p class="value">Unknown (file is encrypted)</p>
                    </div>
                    <div>
                    <p class="label">Domains:</p>
                    <p class="value">Unknown (file is encrypted)</p>
                    </div>
                </div>
                </div>
                """
            else:
                elements= pdfProcess(file_path)
                urlhtml="<br>".join(elements[0]) if  elements[0] else "None"
                iphtml="<br>".join(elements[1]) if elements[1] else "None"
                domainhtml="<br>".join(elements[2]) if elements[2] else "None"
                html_cards += f"""
                <div class="card">
                <p class="label">File Name:</p>
                <p class="value" style="word-break:break-all;">{file_name}</p>
                <div class="grid">
                    <div>
                    <p class="label">File Type:</p>
                    <p class="value">{fileType}</p>
                    </div>
                    <div>
                    <p class="label">Password Exist:</p>
                    <p class="value">{"Password Protected" if passwordExist else "Non-exist"}</p>
                    </div>
                    <div>
                    <p class="label">Urls:</p>
                    <p class="value">{urlhtml} </p>
                    </div>
                    <div>
                    <p class="label">IPs:</p>
                    <p class="value">{iphtml} </p>
                    </div>
                    <div>
                    <p class="label">Domains:</p>
                    <p class="value">{domainhtml} </p>
                    </div>
                </div>
                </div>
                """
        elif fileType.startswith('encrypted-'):
            # OLE-wrapped encrypted Office document — content is inaccessible without password
            base_type = fileType.replace('encrypted-', '').upper() or 'Office'
            html_cards += f"""
                <div class="card">
                <p class="label">File Name:</p>
                <p class="value" style="word-break:break-all;">{file_name}</p>
                <div class="grid">
                    <div>
                    <p class="label">File Type:</p>
                    <p class="value">{base_type} (Encrypted)</p>
                    </div>
                    <div>
                    <p class="label">Password Protected:</p>
                    <p class="value" style="color:var(--danger);">Yes — file is encrypted with a password</p>
                    </div>
                    <div>
                    <p class="label">Encryption:</p>
                    <p class="value">Detected (OLE EncryptedPackage wrapper)</p>
                    </div>
                    <div>
                    <p class="label">Language / Page Count / Macros:</p>
                    <p class="value">Unknown — cannot read encrypted content</p>
                    </div>
                </div>
                </div>
                """

        elif fileType in ["docx", "doc", "docm"]:
            datas= docOck(file_path,fileType)
            html_cards += f"""
                <div class="card">
                <p class="label">File Name:</p>
                <p class="value" style="word-break:break-all;">{file_name}</p>
                <div class="grid">
                    <div>
                    <p class="label">File Type:</p>
                    <p class="value">{datas.get('file_type', fileType)} </p>
                    </div>
                    <div>
                    <p class="label">Language Detected:</p>
                    <p class="value">{datas['language']} </p>
                    </div>
                    <div>
                    <p class="label">Estimated Page Number:</p>
                    <p class="value">{datas['page_count_estimate']} </p>
                    </div>
                    <div>
                    <p class="label">Enryption Detected:</p>
                    <p class="value">{datas.get('encrypted', 'N/A')} </p>
                    </div>
                    <div>
                    <p class="label">Password Exist:</p>
                    <p class="value">{datas['password_protected']} </p>
                    </div>
                    <div>
                    <p class="label">Macros Found:</p>
                    <p class="value">{datas['macros_found']} </p>
                    </div>

                </div>
                </div>
                """

        elif fileType in ["exe", "dll"]:
            strings = extractStrings(file_path)
            urls = strings.get("urls", [])
            ips = strings.get("ip_addresses", [])
            domains = strings.get("domains", [])

            metadata = extractMetadata(file_path)
            arch         = metadata.get('architecture', 'Unknown')
            entropy      = metadata.get('general_entropy', 'N/A')
            file_size    = metadata.get('file_size', 'N/A')
            section_cnt  = metadata.get('section_count', 0)
            compile_date = metadata.get('compile_date', 'Unknown')
            dlls         = metadata.get('imported_dlls', [])
            sections     = metadata.get('sections', [])

            yara_result = yaraRules(file_path)

            html_cards += f"""
            <div class="card">
                <p class="label">File Name:</p>
                <p class="value" style="word-break:break-all;">{file_name}</p>
                <div class="grid">
                    <div>
                        <p class="label">File Type:</p>
                        <p class="value">{fileType}</p>
                    </div>
                    <div>
                        <p class="label">URLs:</p>
                        <p class="value">{'<br>'.join(urls) if urls else 'None found'}</p>
                    </div>
                    <div>
                        <p class="label">IP Addresses:</p>
                        <p class="value">{'<br>'.join(ips) if ips else 'None found'}</p>
                    </div>
                    <div>
                        <p class="label">Domains:</p>
                        <p class="value">{'<br>'.join(domains) if domains else 'None found'}</p>
                    </div>
                    <div>
                        <p class="label">Architecture:</p>
                        <p class="value">{arch}</p>
                    </div>
                    <div>
                        <p class="label">General Entropy:</p>
                        <p class="value">{entropy}</p>
                    </div>
                    <div>
                        <p class="label">File Size:</p>
                        <p class="value">{file_size} bytes</p>
                    </div>
                    <div>
                        <p class="label">Section Count:</p>
                        <p class="value">{section_cnt}</p>
                    </div>
                    <div>
                        <p class="label">Compilation Date:</p>
                        <p class="value">{compile_date}</p>
                    </div>
                    <div>
                        <p class="label">Imported DLLs:</p>
                        <p class="value">{'<br>'.join(dlls) if dlls else 'None'}</p>
                    </div>
                </div>

                <div class="grid" style="margin-top: 1rem;">
                    <div class="label" style="grid-column: 1 / -1;">Section Details:</div>
            """

            for sec in sections:
                sec_name = sec['name']
                sec_entropy = sec['entropy']
                virtual = sec['virtual_size']
                raw = sec['raw_size']
                html_cards += f"""
                    <div style="grid-column: 1 / -1;">
                        <p class="value">
                            <strong>[{sec_name}]</strong><br>
                            Entropy: {sec_entropy} — Virtual Size: {virtual} — Raw Size: {raw}
                        </p>
                    </div>
                """

            html_cards += f"""
                </div>
                <div style="margin-top: 1rem;">
                    <p class="label">YARA Scan Result:</p>
                    <p class="value">{yara_result}</p>
                </div>
            </div>
            """
        else:
            html_cards += f"""
            <div class="card">
                <p class="label">File Name:</p>
                <p class="value" style="word-break:break-all;">{file_name}</p>
                <div class="grid">
                    <div>
                    <p class="label">File Type:</p>
                    <p class="value">{fileType}</p>
                    </div>
                </div>
                </div>
                """
    generate_html_report(html_cards)
    root.destroy()

root = tk.Tk()
root.title("File Analyzer")
tk.Label(root, text="Selected Files:").pack()
listbox = tk.Listbox(root, width=80, height=10)
listbox.pack(padx=5,pady=5)
tk.Button(root, text="Add File", command=add_file).pack(pady=5)
tk.Button(root, text="Done (Analyze All)", command=analyze_all_files).pack(pady=10)
root.mainloop()
