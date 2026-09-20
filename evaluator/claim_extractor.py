"""
evaluator/claim_extractor.py
────────────────────────────
Decomposes forensic agent responses, investigation outputs, and forensic reports
into atomic, verifiable factual claims with domain-specific type classification.
"""

import re
from typing import List, Dict, Any

CLAIM_TYPE_PATTERNS = [
    ("ip_address", r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    ("email", r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b'),
    ("hash", r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b'),
    ("timestamp", r'\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4}\b|\d{1,2}:\d{2}(?::\d{2})?(?: ?[AP]M)?)\b'),
    ("path", r'(?:[a-zA-Z]:\\[a-zA-Z0-9_$\-\\]+|\\[a-zA-Z0-9_$\-\\]{2,}|\bHKLM\\[a-zA-Z0-9_\\\-]+|\bHKCU\\[a-zA-Z0-9_\\\-]+)'),
    ("filename", r'\b[a-zA-Z0-9_#\-\.]+\.(?:docx|doc|pdf|txt|zip|7z|7z\.\d+|exe|dll|db|sqlite|ost|pst|lnk|evtx|reg|iso|cue|raw|dat|png|jpg|jpeg|tsv|csv|E01|dd)\b'),
    ("os_info", r'\b(?:Windows 7|Windows 10|Windows 11|Windows XP|Windows Vista|Ultimate|SP1|Service Pack|Win7|Win10|x64|64-bit|32-bit)\b'),
    ("device", r'\b(?:SanDisk|Cruzer|Cruzer Fit|RM#1|RM#2|RM#3|USBSTOR|INFORMANT-PC|4C530012450531101593|4C530012550531106501)\b'),
    ("application", r'\b(?:CCleaner|Google Chrome|Internet Explorer|Outlook|Google Drive|Dropbox|Eraser|FTK Imager|EnCase|bchunk|VMWare|Microsoft Office)\b'),
    ("username", r'\b(?:informant|admin11|temporary|jdoe|spy|conspirator|Administrator|SYSTEM|LocalService|NetworkService)\b'),
]


def detect_claim_type(text: str) -> str:
    """Classify the primary evidentiary type of an extracted claim."""
    for ctype, pattern in CLAIM_TYPE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return ctype
    return "general_fact"


classify_claim_type = detect_claim_type


def extract_claim_entities(text: str) -> Dict[str, List[str]]:
    """Extract all forensic entities present within an individual claim."""
    entities = {
        "ips": sorted(list(set(re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)))),
        "emails": sorted(list(set(re.findall(r'\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b', text)))),
        "filenames": sorted(list(set(re.findall(r'\b[a-zA-Z0-9_#\-\.]+\.(?:docx|doc|pdf|txt|zip|7z|7z\.\d+|exe|dll|db|sqlite|ost|pst|lnk|evtx|reg|iso|cue|raw|dat|png|jpg|jpeg|tsv|csv|E01|dd)\b', text, re.IGNORECASE)))),
        "paths": sorted(list(set(re.findall(r'(?:[a-zA-Z]:\\[a-zA-Z0-9_$\-\\]+|\\[a-zA-Z0-9_$\-\\]{2,}|\bHKLM\\[a-zA-Z0-9_\\\-]+|\bHKCU\\[a-zA-Z0-9_\\\-]+)', text)))),
        "timestamps": sorted(list(set(re.findall(r'\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?: ?(?:UTC|GMT|IST|\+\d{2}:\d{2}))?)?\b', text)))),
        "hashes": sorted(list(set(re.findall(r'\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b', text)))),
        "usernames": sorted(list(set(re.findall(r'\b(?:informant|admin11|temporary|jdoe|spy|conspirator|Administrator|SYSTEM|LocalService|NetworkService)\b', text, re.IGNORECASE)))),
        "os_info": sorted(list(set(re.findall(r'\b(?:Windows 7 Ultimate|Windows 7|Windows 10|Windows 11|Windows XP|SP1|Service Pack 1|64-bit)\b', text, re.IGNORECASE)))),
        "devices": sorted(list(set(re.findall(r'\b(?:Cruzer Fit|SanDisk|RM#1|RM#2|RM#3|USBSTOR|INFORMANT-PC|4C530012450531101593|4C530012550531106501)\b', text, re.IGNORECASE)))),
        "applications": sorted(list(set(re.findall(r'\b(?:CCleaner|Google Chrome|Internet Explorer|Outlook|Google Drive|Dropbox|Eraser|FTK Imager|EnCase|bchunk|VMWare|Microsoft Office)\b', text, re.IGNORECASE))))
    }
    return entities


def clean_markdown(text: str) -> str:
    """Normalize markdown formatting while preserving factual content."""
    text = re.sub(r'^[#]+\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'[*_]{1,3}', '', text)
    text = re.sub(r'`', '', text)
    text = re.sub(r'^>\s*', '', text, flags=re.MULTILINE)
    return text.strip()


def parse_markdown_table_rows(table_lines: List[str]) -> List[str]:
    """Convert markdown table rows into individual factual statements."""
    if len(table_lines) < 2:
        return []
    
    headers = [c.strip() for c in table_lines[0].split('|') if c.strip()]
    claims = []
    
    for row_line in table_lines[1:]:
        if re.match(r'^\s*\|?[\s\-:|]+\|?\s*$', row_line):
            continue
        cells = [c.strip() for c in row_line.split('|') if c.strip()]
        if not cells:
            continue
        
        if len(cells) == 2:
            k, v = cells[0], cells[1]
            if v and v.lower() not in ('n/a', 'none', '-', '—'):
                claims.append(f"{k} is {v}.")
        elif len(headers) == len(cells):
            parts = [f"{h}: {v}" for h, v in zip(headers, cells) if v and v.lower() not in ('n/a', '-', '—')]
            if parts:
                claims.append(", ".join(parts) + ".")
        else:
            claims.append(" | ".join(cells) + ".")
            
    return claims


def split_into_atomic_sentences(text: str) -> List[str]:
    """Split raw text/prose into distinct, atomic factual statements."""
    lines = text.split('\n')
    extracted = []
    table_buffer = []

    for line in lines:
        sline = line.strip()
        if not sline:
            if table_buffer:
                extracted.extend(parse_markdown_table_rows(table_buffer))
                table_buffer = []
            continue
        
        if sline.startswith('|') and sline.endswith('|'):
            table_buffer.append(sline)
            continue
        else:
            if table_buffer:
                extracted.extend(parse_markdown_table_rows(table_buffer))
                table_buffer = []

        list_match = re.match(r'^(?:[\-\*•]|\d+[\.\)])\s+(.*)$', sline)
        if list_match:
            sline = list_match.group(1).strip()

        sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z0-9"\'\\`])', sline)
        for s in sentences:
            cleaned = clean_markdown(s)
            if len(cleaned) < 3:
                continue

            sub_clauses = re.split(r';\s*|\s+(?:additionally|furthermore|moreover),\s*', cleaned, flags=re.IGNORECASE)
            for clause in sub_clauses:
                c = clause.strip()
                if len(c) >= 4:
                    if not c.endswith(('.', '!', '?')):
                        c += '.'
                    extracted.append(c)

    if table_buffer:
        extracted.extend(parse_markdown_table_rows(table_buffer))

    unique_claims = []
    seen = set()
    for c in extracted:
        norm = re.sub(r'\s+', ' ', c.lower())
        if norm not in seen and len(norm) > 5:
            if re.match(r'^(?:target evidence|incident recorded|forensic report):', norm):
                continue
            seen.add(norm)
            unique_claims.append(c)

    return unique_claims


def extract_claims(response_text: str, question_id: int = 1) -> List[Dict[str, Any]]:
    """
    Main claim extraction pipeline.
    Transforms response text into a list of structured atomic claim objects.
    """
    raw_claims = split_into_atomic_sentences(response_text)
    
    if not raw_claims and response_text.strip():
        raw_claims = [response_text.strip()]

    claim_objects = []
    for idx, c_text in enumerate(raw_claims, start=1):
        claim_id = f"Q{question_id}-C{idx}"
        claim_type = detect_claim_type(c_text)
        entities = extract_claim_entities(c_text)
        
        claim_objects.append({
            "claim_id": claim_id,
            "claim_index": idx,
            "question_id": question_id,
            "claim_text": c_text,
            "claim_type": claim_type,
            "entities": entities
        })

    return claim_objects
