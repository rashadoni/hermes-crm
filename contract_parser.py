"""
contract_parser.py
Parses a lawyer-supplied .docx file, extracts company requisites,
saves the file as the company's contract template, and updates company_details.json.
"""

import os, re, json, html, shutil, zipfile
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "contract_templates")
DETAILS_FILE  = os.path.join(BASE_DIR, "static", "company_details.json")
os.makedirs(TEMPLATES_DIR, exist_ok=True)


# ── helpers ───────────────────────────────────────────────────────────────────

def _load_details() -> dict:
    if os.path.exists(DETAILS_FILE):
        with open(DETAILS_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {}

def _save_details(data: dict):
    with open(DETAILS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()

def _get_xml(docx_path: str) -> str:
    """Extract merged XML text from docx."""
    with zipfile.ZipFile(docx_path, "r") as z:
        with z.open("word/document.xml") as f:
            return f.read().decode("utf-8")

def _get_texts(xml: str) -> list:
    return [html.unescape(t) for t in re.findall(r"<w:t[^>]*>([^<]*)</w:t>", xml) if t.strip()]

def _full_text(xml: str) -> str:
    return " ".join(_get_texts(xml))


# ── company code detection ────────────────────────────────────────────────────

def detect_company_code(filename: str, pricing_keys=None) -> str:
    """
    Try to guess which company this file belongs to from the filename.
    Returns the matched key from pricing_data (or the raw prefix).
    """
    basename = os.path.basename(filename)
    prefix = basename.split(" - ")[0].strip()

    if pricing_keys:
        prefix_upper = prefix.upper().replace(" ", "")
        for key in pricing_keys:
            key_upper = key.upper().replace(" ", "")
            if key_upper == prefix_upper or key_upper.startswith(prefix_upper) or prefix_upper.startswith(key_upper):
                return key
    return prefix


# ── requisite extraction ──────────────────────────────────────────────────────

def extract_requisites(docx_path: str) -> dict:
    """
    Extract all variable fields from a Guven Technology price-schedule docx.
    Returns a dict with contract meta + client sub-dict.
    """
    xml  = _get_xml(docx_path)
    texts = _get_texts(xml)
    full  = " ".join(texts)

    # ── contract / annex ──────────────────────────────────────────────────
    contract_m = re.search(r"(GT/[A-Z\d]+/[\d-]+)", full)
    annex_fn   = re.search(r"Əlavə\s*[№#]\s*(\d+)", os.path.basename(docx_path), re.IGNORECASE)
    annex_doc  = re.search(r"ƏLAVƏ\s*[№#]\s*(\d+)", full, re.IGNORECASE)
    annex_num  = (annex_fn or annex_doc)
    period_m   = re.search(r"(\d{2}\.\d{2}\.\d{4})\s*[-–]\s*(\d{2}\.\d{2}\.\d{4})", full)
    sign_m     = re.search(r"Bakı şəhəri\s+(\d+\s+\w+\s+\d{4}-c[üı]\s+il)", full)

    # ── client name from intro ────────────────────────────────────────────
    cname_m = re.search(
        r'[Ss]ifarişçi["\u201c\u201d\s]+adlandırılacaq[,\s]+["\u201c\u2018]([^"\u201d\u2019]+)["\u201d\u2019]',
        full, re.IGNORECASE)
    client_name = _clean(cname_m.group(1)) if cname_m else ""

    # ── find requisites section ───────────────────────────────────────────
    idx = full.find("REKVİZİT")
    if idx == -1:
        req = full[-2000:]          # fallback: last 2000 chars
    else:
        req = full[idx:]

    # All VOENs in requisites (Guven's = 1406777811, also bank VOEN 1700767721)
    voens = re.findall(r"VÖEN[:\s-]*(\d{7,})", req)
    client_voen = next(
        (v for v in voens if v not in ("1406777811", "1700767721")),
        voens[1] if len(voens) > 1 else ""
    )

    # H/H accounts
    hh_accounts = re.findall(r"H/H[:\s]*(AZ\w+)", req)
    client_hh = hh_accounts[1] if len(hh_accounts) > 1 else (hh_accounts[0] if hh_accounts else "")

    # M/H accounts
    mh_accounts = re.findall(r"M/H[:\s]*(AZ\w+)", req)
    client_mh = mh_accounts[1] if len(mh_accounts) > 1 else ""

    # Client section (after Guven's signatory)
    client_req_idx = req.find("direktoru\n") if "direktoru\n" in req else req.find("direktoru")
    client_req = req[client_req_idx + 10:] if client_req_idx > 0 else req

    # Bank
    bank_m = re.search(r'(?:Bank|BANK)[:\s]*["\u201c]([^"\u201d]+)["\u201d]', client_req)
    client_bank = _clean(bank_m.group(1)) if bank_m else "PAŞA Bank"

    bank_voen_m = re.search(r"(?:Bankın VÖEN[^\d]*|VÖEN[:\s]*)(\d{7,})", client_req)
    bank_code_m = re.search(r"[Kk]odu?[:\s]+(\d+)", client_req)
    swift_m     = re.search(r"S\.?W\.?I\.?F\.?T\.?[:\s]*([A-Z0-9]{8,11})", client_req)

    # Client address
    addr_m = re.search(
        r"(?:Hüquqi|Faktiki)?\s*[Üü]nvan[:\s]+([^\n]+?)(?=\s*VÖEN|$)",
        client_req[:600])
    client_addr = _clean(addr_m.group(1)) if addr_m else ""

    # Director from intro paragraph
    director_name = ""
    director_title = ""
    if client_voen:
        dir_m = re.search(
            r"VÖEN:\s*" + re.escape(client_voen) +
            r"\s*\)[^,]*,\s*(?:Cəmiyyətin\s+|Birliyin\s+|İdarə\s+heyətinin\s+)?([^,\n]+?)\s+"
            r"([\w\s]+oğlu|[\w\s]+qızı|[A-ZƏÜÖİŞÇĞ][a-zəüöişçğ]+\s+[A-ZƏÜÖİŞÇĞ][a-zəüöişçğ]+"
            r"(?:\s+[A-ZƏÜÖİŞÇĞ][a-zəüöişçğ]+)?)\s+şəxsində",
            full)
        if dir_m:
            director_title = _clean(dir_m.group(1))
            director_name  = _clean(dir_m.group(2))

    # Signatory from requisites bottom
    sig_m = re.search(
        r"_{5,}[^_\n]*?([A-ZƏÜÖİŞÇĞ][a-zəüöişçğ]+\s+[A-ZƏÜÖİŞÇĞ][a-zəüöişçğ]+"
        r"(?:\s+[A-ZƏÜÖİŞÇĞ][a-zəüöişçğ]+)?)\s+[«\"\u201c]",
        client_req)
    client_signatory = _clean(sig_m.group(1)) if sig_m else director_name

    return {
        "template_file": os.path.basename(docx_path),
        "contract_number": contract_m.group(1) if contract_m else "",
        "annex_number": annex_num.group(1).zfill(2) if annex_num else "",
        "signing_date": _clean(sign_m.group(1)) if sign_m else "",
        "period_start": period_m.group(1) if period_m else "01.01.2026",
        "period_end":   period_m.group(2) if period_m else "31.12.2026",
        "client": {
            "legal_name":     client_name,
            "voen":           client_voen,
            "director_name":  director_name or client_signatory,
            "director_title": director_title,
            "address":        client_addr,
            "bank":           client_bank,
            "bank_voen":      _clean(bank_voen_m.group(1)) if bank_voen_m else "1700767721",
            "bank_code":      _clean(bank_code_m.group(1)) if bank_code_m else "505141",
            "mh":             client_mh,
            "hh":             client_hh,
            "swift":          _clean(swift_m.group(1)) if swift_m else "PAHAAZ22",
        },
    }


# ── main import function ──────────────────────────────────────────────────────

def import_contract_file(
    src_path: str,
    company_code=None,
    pricing_keys=None,
) -> dict:
    """
    Import a lawyer-supplied docx file:
      1. Detect company code from filename (or use provided code)
      2. Extract requisites
      3. Save the file to contract_templates/{code}.docx
      4. Update company_details.json
    Returns { "code": ..., "data": {...}, "template_path": ... }
    """
    code = company_code or detect_company_code(src_path, pricing_keys)
    data = extract_requisites(src_path)

    # Store template — whitelist sanitization to prevent path traversal
    safe_code = re.sub(r'[^a-zA-Z0-9\u00C0-\u024F\u0400-\u04FF _\-]', "_", code)
    safe_code = safe_code.replace("..", "").strip()[:100]
    tpl_path  = os.path.join(TEMPLATES_DIR, f"{safe_code}.docx")
    # Verify resolved path is within TEMPLATES_DIR
    if not os.path.realpath(tpl_path).startswith(os.path.realpath(TEMPLATES_DIR)):
        raise ValueError(f"Invalid company code: path traversal detected")
    shutil.copy2(src_path, tpl_path)

    # Update company_details.json
    details = _load_details()
    if code in details:
        # Merge: keep existing values if new ones are empty
        existing = details[code]
        for k, v in data.items():
            if k == "client":
                for ck, cv in v.items():
                    if cv:
                        existing.setdefault("client", {})[ck] = cv
            elif v:
                existing[k] = v
    else:
        details[code] = data

    details[code]["template_file"] = os.path.basename(tpl_path)
    details[code]["last_imported"]  = datetime.now().isoformat(timespec="seconds")
    _save_details(details)

    return {"code": code, "data": details[code], "template_path": tpl_path}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 contract_parser.py <file.docx> [company_code]")
        sys.exit(1)
    filepath = sys.argv[1]
    code_arg = sys.argv[2] if len(sys.argv) > 2 else None
    result = import_contract_file(filepath, code_arg)
    print(json.dumps(result["data"], ensure_ascii=False, indent=2))
