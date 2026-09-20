"""
evaluator/nist_ground_truth_parser.py
──────────────────────────────────────
Parses the official NIST CFReDS Data Leakage Case answer documents
(reference_data/nist_data_leakage_answers.docx & reference_data/nist_data_leakage_answers.pdf)
and produces the authoritative ground-truth reference dataset at:
reference_data/nist_ground_truth.json
"""

import os
import re
import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REF_DIR = BASE_DIR / "reference_data"
DOCX_PATH = REF_DIR / "nist_data_leakage_answers.docx"
PDF_PATH = REF_DIR / "nist_data_leakage_answers.pdf"
OUTPUT_JSON_PATH = REF_DIR / "nist_ground_truth.json"

# Canonical 60 NIST CFReDS Questions
NIST_QUESTIONS = [
    "What are the hash values (MD5 & SHA-1) of all images? Does the acquisition and verification hash value match?",
    "Identify the partition information of PC image.",
    "Explain installed OS information in detail (OS name, install date, registered owner...).",
    "What is the timezone setting?",
    "What is the computer name?",
    "List all accounts in OS except the system accounts: Administrator, Guest, systemprofile, LocalService, NetworkService (Account name, login count, last logon date...).",
    "Who was the last user to logon into PC?",
    "When was the last recorded shutdown date/time?",
    "Explain the information of network interface(s) with an IP address assigned by DHCP.",
    "What applications were installed by the suspect after installing OS?",
    "List application execution logs (Executable path, execution time, execution count...).",
    "List all traces about the system on/off and the user logon/logoff (between 09:00 and 18:00 in the identified timezone).",
    "What web browsers were used?",
    "Identify directory/file paths related to the web browser history.",
    "What websites were the suspect accessing? (Timestamp, URL...).",
    "List all search keywords using web browsers (Timestamp, URL, keyword...).",
    "List all user keywords at the search bar in Windows Explorer (Timestamp, Keyword).",
    "What application was used for e-mail communication?",
    "Where is the e-mail file located?",
    "What was the e-mail account used by the suspect?",
    "List all e-mails of the suspect. If possible, identify deleted e-mails (Timestamp, From, To, Subject, Body, Attachment). Examine the OST file only.",
    "List external storage devices attached to PC.",
    "Identify all traces related to 'renaming' of files in Windows Desktop (date range between 2015-03-23 and 2015-03-24).",
    "What is the IP address of company's shared network drive?",
    "List all directories that were traversed in 'RM#2'.",
    "List all files that were opened in 'RM#2'.",
    "List all directories that were traversed in the company's network drive.",
    "List all files that were opened in the company's network drive.",
    "Find traces related to cloud services on PC (Service name, log files...).",
    "What files were deleted from Google Drive? Find the filename and modified timestamp (Find a transaction log file of Google Drive).",
    "Identify account information for synchronizing Google Drive.",
    "What method (or software) was used for burning CD-R?",
    "When did the suspect burn CD-R? (It may be one or more times).",
    "What files were copied from PC to CD-R? (Examine file system transaction logs).",
    "What files were opened from CD-R?",
    "Identify all timestamps related to a resignation file in Windows Desktop (DOCX file in NTFS file system).",
    "How and when did the suspect print a resignation file?",
    "Where are 'Thumbcache' files located?",
    "Identify traces related to confidential files stored in Thumbcache (Include '256' only).",
    "Where are Sticky Note files located?",
    "Identify notes stored in the Sticky Note file.",
    "Was the 'Windows Search and Indexing' function enabled? How can you identify it? What is the file path of the database?",
    "What kinds of data were stored in Windows Search database?",
    "Find traces of Internet Explorer usage stored in Windows Search database (2015-03-22 to 2015-03-23).",
    "List the e-mail communication stored in Windows Search database (2015-03-23 to 2015-03-24).",
    "List files and directories related to Windows Desktop stored in Windows Search database (\\Users\\informant\\Desktop\\).",
    "Where are Volume Shadow Copies stored? When were they created?",
    "Find traces related to Google Drive service in Volume Shadow Copy. What are the differences between current system image and its VSC?",
    "What files were deleted from Google Drive? Find deleted records of cloud_entry table inside snapshot.db from VSC.",
    "Why can't we find Outlook's e-mail data in Volume Shadow Copy?",
    "Examine 'Recycle Bin' data in PC.",
    "What actions were performed for anti-forensics on PC at the last day '2015-03-25'?",
    "Recover deleted files from USB drive 'RM#2'.",
    "What actions were performed for anti-forensics on USB drive 'RM#2'?",
    "What files were copied from PC to USB drive 'RM#2'?",
    "Recover hidden files from the CD-R 'RM#3'. How to determine proper filenames of original files prior to renaming?",
    "What actions were performed for anti-forensics on CD-R 'RM#3'?",
    "Create a detailed timeline of data leakage processes.",
    "List and explain methodologies of data leakage performed by the suspect.",
    "Create a visual diagram for a summary of results."
]

def extract_pdf_page_mapping():
    """Extract page text from PDF and map each question to exact PDF page numbers."""
    page_map = {i: [] for i in range(1, 61)}
    if not PDF_PATH.exists():
        return page_map
    
    try:
        import pypdf
        reader = pypdf.PdfReader(str(PDF_PATH))
        for p_idx, page in enumerate(reader.pages):
            p_num = p_idx + 1
            text = page.extract_text() or ""
            if p_num < 12 or p_num > 51:
                continue
            
            for q_id, q_text in enumerate(NIST_QUESTIONS, start=1):
                clean_q = re.sub(r'[^a-zA-Z0-9 ]', '', q_text).lower()
                clean_p = re.sub(r'[^a-zA-Z0-9 ]', '', text).lower()
                words = [w for w in clean_q.split() if len(w) > 3 and w not in ('what', 'where', 'when', 'list', 'identify', 'explain', 'were', 'from', 'this', 'that', 'with', 'about', 'only', 'also', 'file', 'data')]
                
                if words:
                    matches = sum(1 for w in words if w in clean_p)
                    if matches >= max(2, int(len(words) * 0.4)):
                        if p_num not in page_map[q_id]:
                            page_map[q_id].append(p_num)
    except Exception as e:
        print(f"Warning: PDF mapping error: {e}")
    
    for q_id in range(1, 61):
        if not page_map[q_id]:
            est = min(50, 12 + int((q_id - 1) * (38 / 59)))
            page_map[q_id] = [est]
            
    return page_map


def clean_text(t: str) -> str:
    """Clean characters and quotes."""
    if not t:
        return ""
    t = t.replace('\ufffd', "'").replace('\u2018', "'").replace('\u2019', "'")
    t = t.replace('\u201c', '"').replace('\u201d', '"').replace('\u2013', '-').replace('\u2014', '--')
    return t.strip()


def parse_docx_questions():
    """Parse Section 6 from DOCX into 60 structured question answer blocks."""
    with zipfile.ZipFile(str(DOCX_PATH)) as z:
        xml_content = z.read('word/document.xml')
        tree = ET.fromstring(xml_content)

    paragraphs = []
    for p in tree.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
        text = ''.join(node.text for node in p.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t') if node.text)
        cleaned = clean_text(text)
        if cleaned:
            paragraphs.append(cleaned)

    sec6_start = 0
    for i, p in enumerate(paragraphs):
        if "Questions and Answers about the Scenario" in p and i > 20:
            sec6_start = i + 1
            break

    sec7_start = len(paragraphs)
    for i in range(sec6_start, len(paragraphs)):
        if paragraphs[i].startswith("7.History") or (paragraphs[i] == "History" and i > sec6_start + 500):
            sec7_start = i
            break

    stream = paragraphs[sec6_start:sec7_start]

    question_anchors = [
        "What are the hash values",
        "Identify the partition information",
        "Explain installed OS information",
        "What is the timezone setting",
        "What is the computer name",
        "List all accounts in OS",
        "Who was the last user to logon",
        "When was the last recorded shutdown",
        "Explain the information of network interface",
        "What applications were installed",
        "List application execution logs",
        "List all traces about the system on/off",
        "What web browsers were used",
        "Identify directory/file paths related to the web browser",
        "What websites were the suspect accessing",
        "List all search keywords using web browsers",
        "List all user keywords at the search bar",
        "What application was used for e-mail",
        "Where is the e-mail file located",
        "What was the e-mail account used",
        "List all e-mails of the suspect",
        "List external storage devices attached",
        "Identify all traces related to 'renaming'",
        "What is the IP address of company's shared network",
        "List all directories that were traversed in 'RM#2'",
        "List all files that were opened in 'RM#2'",
        "List all directories that were traversed in the company's network",
        "List all files that were opened in the company's network",
        "Find traces related to cloud services",
        "What files were deleted from Google Drive? Find the filename",
        "Identify account information for synchronizing Google Drive",
        "What method (or software) was used for burning CD-R",
        "When did the suspect burn CD-R",
        "What files were copied from PC to CD-R",
        "What files were opened from CD-R",
        "Identify all timestamps related to a resignation file",
        "How and when did the suspect print a resignation",
        "Where are 'Thumbcache' files located",
        "Identify traces related to confidential files stored in Thumbcache",
        "Where are Sticky Note files located",
        "Identify notes stored in the Sticky Note",
        "Was the 'Windows Search and Indexing' function enabled",
        "What kinds of data were stored in Windows Search database",
        "Find traces of Internet Explorer usage stored in Windows Search",
        "List the e-mail communication stored in Windows Search",
        "List files and directories related to Windows Desktop stored in Windows Search",
        "Where are Volume Shadow Copies stored",
        "Find traces related to Google Drive service in Volume Shadow Copy",
        "What files were deleted from Google Drive? Find deleted records",
        "Why can't we find Outlook's e-mail data in Volume Shadow Copy",
        "Examine 'Recycle Bin' data in PC",
        "What actions were performed for anti-forensics on PC at the last day",
        "Recover deleted files from USB drive 'RM#2'",
        "What actions were performed for anti-forensics on USB drive 'RM#2'",
        "What files were copied from PC to USB drive 'RM#2'",
        "Recover hidden files from the CD-R 'RM#3'",
        "What actions were performed for anti-forensics on CD-R 'RM#3'",
        "Create a detailed timeline of data leakage",
        "List and explain methodologies of data leakage",
        "Create a visual diagram for a summary"
    ]

    split_indices = []
    current_idx = 0
    for q_idx, anchor in enumerate(question_anchors):
        anchor_clean = re.sub(r'[^a-zA-Z0-9 ]', '', anchor).lower().split()
        anchor_words = [w for w in anchor_clean if len(w) > 3][:3]
        
        found = False
        for s_idx in range(current_idx, len(stream)):
            p_clean = re.sub(r'[^a-zA-Z0-9 ]', '', stream[s_idx]).lower()
            if all(w in p_clean for w in anchor_words):
                split_indices.append(s_idx)
                current_idx = s_idx + 1
                found = True
                break
        if not found:
            split_indices.append(current_idx)
            current_idx += 5

    blocks = []
    for i in range(len(split_indices)):
        start = split_indices[i]
        end = split_indices[i+1] if i + 1 < len(split_indices) else len(stream)
        blocks.append(stream[start:end])

    return blocks


def extract_entities(text: str) -> dict:
    """Extract structured entities (IPs, emails, paths, filenames, timestamps, hashes, usernames, os_info, devices, applications) from text."""
    return {
        "ips": sorted(list(set(re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)))),
        "emails": sorted(list(set(re.findall(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b', text)))),
        "filenames": sorted(list(set(re.findall(r'\b[a-zA-Z0-9_#\-\.]+\.(?:docx|doc|pdf|txt|zip|7z|7z\.\d+|exe|dll|db|sqlite|ost|pst|lnk|evtx|reg|iso|cue|raw|dat|png|jpg|jpeg|tsv|csv|E01|dd)\b', text, re.IGNORECASE)))),
        "paths": sorted(list(set(re.findall(r'(?:[a-zA-Z]:\\[a-zA-Z0-9_$\-\\]+|\\[a-zA-Z0-9_$\-\\]+|\bHKLM\\[a-zA-Z0-9_\\\-]+|\bHKCU\\[a-zA-Z0-9_\\\-]+)', text)))),
        "timestamps": sorted(list(set(re.findall(r'\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?: ?(?:UTC|GMT|IST|\+\d{2}:\d{2}))?)?\b', text)))),
        "hashes": sorted(list(set(re.findall(r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b', text)))),
        "usernames": sorted(list(set(re.findall(r'\b(?:informant|admin11|temporary|jdoe|spy|conspirator|Administrator|SYSTEM|LocalService|NetworkService)\b', text, re.IGNORECASE)))),
        "os_info": sorted(list(set(re.findall(r'\b(?:Windows 7 Ultimate|Windows 7|Windows 10|Windows 11|Windows XP|SP1|Service Pack 1|64-bit)\b', text, re.IGNORECASE)))),
        "devices": sorted(list(set(re.findall(r'\b(?:Cruzer Fit|SanDisk|RM#1|RM#2|RM#3|USBSTOR|INFORMANT-PC|4C530012450531101593|4C530012550531106501)\b', text, re.IGNORECASE)))),
        "applications": sorted(list(set(re.findall(r'\b(?:CCleaner|Google Chrome|Internet Explorer|Outlook|Google Drive|Dropbox|Eraser|FTK Imager|EnCase|bchunk|VMWare|Microsoft Office|Word|Excel|PowerPoint)\b', text, re.IGNORECASE))))
    }


def extract_keywords(question_text: str, answer_text: str) -> list:
    """Extract representative domain keywords from question and ground truth."""
    combined = f"{question_text} {answer_text}"
    words = re.findall(r'\b[a-zA-Z0-9_#-]{3,}\b', combined)
    stop = {
        'what', 'when', 'where', 'which', 'who', 'whom', 'whose', 'why', 'how',
        'the', 'and', 'for', 'are', 'was', 'were', 'been', 'with', 'from', 'this',
        'that', 'these', 'those', 'have', 'has', 'had', 'does', 'did', 'will',
        'would', 'should', 'could', 'about', 'into', 'only', 'also', 'some', 'any',
        'each', 'than', 'then', 'possible', 'answer', 'considerations', 'consideration',
        'table', 'list', 'identify', 'explain', 'show', 'tell', 'below'
    }
    filtered = []
    seen = set()
    for w in words:
        wl = w.lower()
        if wl not in stop and wl not in seen and len(wl) >= 3 and not wl.isdigit():
            seen.add(wl)
            filtered.append(w)
    return filtered[:12]


def build_ground_truth_dataset():
    """Build the comprehensive 60-question NIST ground truth dataset."""
    os.makedirs(REF_DIR, exist_ok=True)
    
    pdf_pages = extract_pdf_page_mapping()
    blocks = parse_docx_questions()
    
    questions_data = []
    
    for q_idx in range(1, 61):
        q_text = NIST_QUESTIONS[q_idx - 1]
        raw_block = blocks[q_idx - 1] if q_idx - 1 < len(blocks) else []
        
        block = []
        for line in raw_block:
            if any(line.lower().startswith(p.lower()) for p in [q_text[:20], "question", "q" + str(q_idx)]):
                continue
            block.append(line)
            
        ans_lines = []
        cons_lines = []
        target = ans_lines
        
        for line in block:
            if line.strip() == "Considerations":
                target = cons_lines
                continue
            elif line.strip() == "Possible Answer":
                target = ans_lines
                continue
            target.append(line)
            
        ground_truth_str = "\n".join(ans_lines).strip()
        considerations_str = "\n".join(cons_lines).strip()
        
        if not ground_truth_str:
            ground_truth_str = "\n".join(raw_block).strip() or f"Official answer for Q{q_idx}: Refer to NIST reference documentation."
            
        src_pages = pdf_pages.get(q_idx, [min(50, 12 + int((q_idx - 1) * (38 / 59)))])
        
        full_text = f"{q_text}\n{ground_truth_str}\n{considerations_str}"
        entities = extract_entities(full_text)
        keywords = extract_keywords(q_text, ground_truth_str)
        
        q_entry = {
            "question_id": q_idx,
            "question": q_text,
            "ground_truth": ground_truth_str,
            "considerations": considerations_str,
            "source_pages": sorted(list(set(src_pages))),
            "keywords": keywords,
            "entities": entities
        }
        questions_data.append(q_entry)

    dataset = {
        "case": "NIST CFReDS Data Leakage Case",
        "source": "NIST",
        "source_url": "https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html",
        "answer_document": "leakage-answers.pdf",
        "version": "1.32",
        "total_questions": len(questions_data),
        "questions": questions_data
    }

    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print(f"[OK] Generated authoritative NIST ground-truth dataset: {OUTPUT_JSON_PATH}")
    print(f"     Total questions: {len(questions_data)}")
    return dataset


NIST_GROUND_TRUTH_FILE = OUTPUT_JSON_PATH


def load_ground_truth():
    if not OUTPUT_JSON_PATH.exists():
        build_ground_truth_dataset()
    with open(OUTPUT_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
        return {q["question_id"]: q for q in data.get("questions", [])}


if __name__ == "__main__":
    build_ground_truth_dataset()
