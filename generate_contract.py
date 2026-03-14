"""
generate_contract.py
Generates a filled .docx contract for a company using:
  - Their template from contract_templates/{code}.docx
  - Current prices from static/pricing_data.json
  - Requisites from static/company_details.json
"""

import os, re, json, zipfile, shutil, copy, html, unicodedata
from io import BytesIO
from datetime import datetime


def _nfc(s: str) -> str:
    """NFC-normalize + uppercase for robust Unicode key comparison.
    Handles cases like TABİA stored as I+combining-dot vs precomposed İ."""
    return unicodedata.normalize("NFC", s).upper()

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "contract_templates")
PRICING_FILE  = os.path.join(BASE_DIR, "static", "pricing_data.json")
DETAILS_FILE  = os.path.join(BASE_DIR, "static", "company_details.json")
OUTPUT_DIR    = os.path.join(BASE_DIR, "static", "generated")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Fallback template when company has no specific template
FALLBACK_TEMPLATE = "AzMade.docx"

# Mapping: pricing_data category key → full display name used in contracts
CAT_FULL_NAMES = {
    "İT İnfrastruktur":          "İT İnfrastruktur və Server Xidmətləri",
    "Məlumat Bazası":             "Məlumat Bazası və Məlumat İdarəetmə",
    "Bulud Xidmətləri":           "Bulud Xidmətləri və \u2018as-a-Service\u2019 Platformaları",
    "Avtomatlaşdırılmış Sistemlər": "Avtomatlaşdırılmış Sistemlər və Biznes Proqramları",
    "SaaS Biznes Process":        "SaaS Biznes Process",
    "Video, Monitorinq":          "Video, Monitorinq və Giriş-Çıxışa Nəzarət Sistemləri",
    "İnformasiya Təhlükəsizlik":  "İnformasiya Təhlükəsizlik Xidmətləri",
    "Konsaltinq və Layihə":       "Konsaltinq və Layihə Xidmətləri",
    "Audit və Uyğunluq":          "Audit və Uyğunluq Xidmətləri",
    "Təlim və Maarifləndirmə":    "Təlim və Maarifləndirmə",
    "HelpDesk və Texniki Dəstək": "HelpDesk və Texniki Dəstək Xidmətləri",
}

# ── helpers ───────────────────────────────────────────────────────────────────

def _load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def _fmt(val: float) -> str:
    """Format a price: 1341.80 → '1,341.80 ₼'. Rejects negative values."""
    val = max(0, float(val))
    return f"{val:,.2f} ₼"

def _fmt_bare(val: float) -> str:
    """Format without currency symbol: 61.40"""
    return f"{val:,.2f}"

def _esc_xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def _get_xml(docx_path: str) -> str:
    with zipfile.ZipFile(docx_path, "r") as z:
        return z.read("word/document.xml").decode("utf-8")

def _read_all_parts(docx_path: str) -> dict:
    """Read all files from docx zip."""
    parts = {}
    with zipfile.ZipFile(docx_path, "r") as z:
        for name in z.namelist():
            parts[name] = z.read(name)
    return parts

def _write_docx(parts: dict, doc_xml: str, output_path: str):
    """Write docx with modified document.xml."""
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            if name == "word/document.xml":
                z.writestr(name, doc_xml.encode("utf-8"))
            else:
                z.writestr(name, data)


# ── run-merging (simplified) ──────────────────────────────────────────────────

def _merge_runs(xml: str) -> str:
    """
    Merge adjacent <w:r> elements that share the same <w:rPr> formatting.
    This makes text substitution reliable.
    """
    def _rpr(run_xml):
        m = re.search(r"<w:rPr>(.*?)</w:rPr>", run_xml, re.DOTALL)
        return m.group(1) if m else ""

    def _text(run_xml):
        parts = re.findall(r"<w:t[^>]*>([^<]*)</w:t>", run_xml)
        return "".join(parts)

    def _has_preserve(run_xml):
        return 'xml:space="preserve"' in run_xml

    def merge_in_para(para_xml):
        runs = re.split(r"(<w:r\b[^>]*>.*?</w:r>)", para_xml, flags=re.DOTALL)
        result = []
        i = 0
        while i < len(runs):
            seg = runs[i]
            if not re.match(r"<w:r\b", seg):
                result.append(seg)
                i += 1
                continue
            # It's a run — try to merge with next runs that have same rPr
            combined_text = _text(seg)
            rpr = _rpr(seg)
            j = i + 1
            while j < len(runs):
                nxt = runs[j]
                if re.match(r"<w:r\b", nxt) and _rpr(nxt) == rpr:
                    combined_text += _text(nxt)
                    j += 1
                else:
                    break
            # Rebuild merged run
            preserve = ' xml:space="preserve"' if " " in combined_text else ""
            rpr_block = f"<w:rPr>{rpr}</w:rPr>" if rpr else ""
            merged = (
                f'<w:r><w:rPr>{rpr}</w:rPr><w:t{preserve}>'
                f'{_esc_xml(combined_text)}</w:t></w:r>'
            ) if rpr else (
                f'<w:r><w:t{preserve}>{_esc_xml(combined_text)}</w:t></w:r>'
            )
            result.append(merged)
            i = j
        return "".join(result)

    # Apply per-paragraph
    def process_para(m):
        return merge_in_para(m.group(0))

    return re.sub(r"<w:p\b[^>]*>.*?</w:p>", process_para, xml, flags=re.DOTALL)


# ── text substitution ─────────────────────────────────────────────────────────

def _replace_in_runs(xml: str, old: str, new: str) -> str:
    """Replace `old` text within <w:t> elements, preserving surrounding XML."""
    escaped_old = _esc_xml(old)
    escaped_new = _esc_xml(new)
    return xml.replace(escaped_old, escaped_new)


def _replace_variables(xml: str, details: dict, params: dict) -> str:
    """Replace all variable fields from details + params."""
    c = details.get("client", {})

    # Helper to replace in <w:t> nodes
    def sub(old, new):
        nonlocal xml
        if old and old in xml:
            xml = _replace_in_runs(xml, old, new or "")

    old_name     = c.get("_original_name", c.get("legal_name", ""))
    new_name     = c.get("legal_name", "")
    old_voen     = c.get("_original_voen", c.get("voen", ""))
    new_voen     = c.get("voen", "")
    old_director = c.get("_original_director", c.get("director_name", ""))
    new_director = c.get("director_name", "")
    old_title    = c.get("_original_title", c.get("director_title", ""))
    new_title    = c.get("director_title", "")
    old_contract = details.get("_original_contract", details.get("contract_number", ""))
    new_contract = params.get("contract_number", details.get("contract_number", ""))
    old_annex    = details.get("_original_annex", details.get("annex_number", ""))
    new_annex    = params.get("annex_number", details.get("annex_number", ""))
    old_sign     = details.get("_original_signing", details.get("signing_date", ""))
    new_sign     = params.get("signing_date", details.get("signing_date", ""))
    old_start    = details.get("period_start", "01.01.2026")
    new_start    = params.get("period_start", old_start)
    old_end      = details.get("period_end", "31.12.2026")
    new_end      = params.get("period_end", old_end)

    # Client name (multiple places)
    sub(old_name, new_name)
    # VÖEN
    sub(old_voen, new_voen)
    # Director
    sub(old_director, new_director)
    # Title
    sub(old_title, new_title)
    # Contract number
    sub(old_contract, new_contract)
    # Annex number (e.g., "03" → "04")
    if old_annex and new_annex and old_annex != new_annex:
        sub(f"ƏLAVƏ № {old_annex}", f"ƏLAVƏ № {new_annex}")
        sub(f"Əlavə № {old_annex}", f"Əlavə № {new_annex}")
        sub(f"Əlavə #{old_annex}", f"Əlavə #{new_annex}")
    # Period
    sub(old_start, new_start)
    sub(old_end, new_end)
    # Signing date
    sub(old_sign, new_sign)
    # Bank details
    sub(c.get("_original_hh", c.get("hh", "")), c.get("hh", ""))
    sub(c.get("_original_mh", c.get("mh", "")), c.get("mh", ""))

    return xml


# ── table builders ────────────────────────────────────────────────────────────

def _get_tables(xml: str) -> list:
    return re.findall(r"<w:tbl\b[^>]*>.*?</w:tbl>", xml, re.DOTALL)

def _get_rows(tbl: str) -> list:
    return re.findall(r"<w:tr\b[^>]*>.*?</w:tr>", tbl, re.DOTALL)

def _get_cells(row: str) -> list:
    return re.findall(r"<w:tc\b[^>]*>.*?</w:tc>", row, re.DOTALL)

def _cell_text(cell: str) -> str:
    return html.unescape("".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", cell)))

def _replace_cell_text(cell: str, new_text: str) -> str:
    """
    Replace all text in a cell with new_text.
    Puts new_text in the FIRST <w:t> element and empties all others.
    This prevents text duplication when a cell has multiple runs.
    """
    escaped = _esc_xml(new_text)
    preserve = ' xml:space="preserve"' if " " in new_text else ""
    first = [True]

    def replacer(m):
        if first[0]:
            first[0] = False
            return f'{m.group(1)}{escaped}{m.group(2)}'
        else:
            return f'{m.group(1)}{m.group(2)}'

    return re.sub(r"(<w:t[^>]*>)[^<]*(</w:t>)", replacer, cell)

def _clone_row_with_values(template_row: str, cell_values: list) -> str:
    """Clone a template row and set cell text values."""
    cells = _get_cells(template_row)
    if not cells:
        return template_row
    # Build new cells
    new_cells = []
    for i, cell in enumerate(cells):
        val = cell_values[i] if i < len(cell_values) else ""
        new_cells.append(_replace_cell_text(cell, val))
    # Rebuild row: replace cells
    result = template_row
    for old_cell, new_cell in zip(cells, new_cells):
        result = result.replace(old_cell, new_cell, 1)
    return result


def _ensure_keep_next(row_xml):
    """
    Inject <w:keepNext/> into every <w:pPr> in the row so Word keeps
    this row on the same page as the next row (prevents header/data split).
    If a paragraph has no <w:pPr>, create one.
    """
    def add_keep(m):
        ppr = m.group(0)
        if '<w:keepNext' in ppr:
            return ppr  # already present
        # Insert <w:keepNext/> right after <w:pPr> or <w:pPr ...>
        return re.sub(r'(<w:pPr[^>]*>)', r'\1<w:keepNext/>', ppr, count=1)

    # If <w:pPr> exists, inject keepNext into it
    if '<w:pPr' in row_xml:
        return re.sub(r'<w:pPr[^>]*>.*?</w:pPr>', add_keep, row_xml, flags=re.DOTALL)
    # If no <w:pPr>, add one inside each <w:p> or <w:p ...>
    return re.sub(r'(<w:p\b[^>]*>)', r'\1<w:pPr><w:keepNext/></w:pPr>', row_xml)


def rebuild_summary_table(tbl: str, non_zero_cats: list) -> str:
    """
    Rebuild Table 0 (summary: category name + monthly total).
    non_zero_cats: list of (display_name, total_float) tuples
    """
    rows = _get_rows(tbl)
    if len(rows) < 3:
        return tbl

    header_row = rows[0]
    # Find a template data row (one with 3 cells and a number)
    data_row_tpl = None
    total_row_tpl = None
    for r in rows[1:]:
        cells = _get_cells(r)
        if len(cells) == 3 and data_row_tpl is None:
            data_row_tpl = r
        elif len(cells) <= 2:
            total_row_tpl = r

    if not data_row_tpl:
        return tbl

    grand_total = sum(t for _, t in non_zero_cats)

    new_rows = [header_row]
    for idx, (cat_name, cat_total) in enumerate(non_zero_cats, start=1):
        new_rows.append(_clone_row_with_values(
            data_row_tpl,
            [str(idx), cat_name, _fmt(cat_total)]
        ))

    # Grand total row
    if total_row_tpl:
        cells = _get_cells(total_row_tpl)
        if len(cells) >= 2:
            new_total_row = _clone_row_with_values(
                total_row_tpl,
                ["CƏMİ: (ƏDV 18%) xaric olmaqla", f"     {_fmt(grand_total)} "]
            )
        else:
            new_total_row = total_row_tpl
        new_rows.append(new_total_row)

    # Rebuild table XML
    tbl_start = re.match(r"(<w:tbl\b[^>]*>(?:.*?<w:tblPr>.*?</w:tblPr>)?(?:.*?<w:tblGrid>.*?</w:tblGrid>)?)", tbl, re.DOTALL)
    tbl_header = tbl_start.group(1) if tbl_start else "<w:tbl>"
    return tbl_header + "".join(new_rows) + "</w:tbl>"


def _parse_template_sections(rows):
    """
    Parse Table 1 rows (after title+header) into sections, one per category.
    Each section = { 'header': row, 'services': [rows...], 'subtotal': row,
                     'display_name': str (text from header cell) }
    """
    sections = []
    current = None
    for r in rows:
        cells = _get_cells(r)
        ncells = len(cells)
        if ncells == 1:
            # Category header row — start a new section
            if current:
                sections.append(current)
            txt = _cell_text(cells[0]).strip()
            current = {'header': r, 'services': [], 'subtotal': None, 'display_name': txt}
        elif current and ncells == 2:
            # Subtotal (Cəmi) row — end of section
            current['subtotal'] = r
            sections.append(current)
            current = None
        elif current and ncells >= 6:
            # Service row
            current['services'].append(r)
    if current:
        sections.append(current)
    return sections


def rebuild_detail_table(tbl, non_zero_cats, pricing_cats):
    """
    Rebuild Table 1 (detail services).
    HYBRID mode: categories WITH individual service data are rebuilt from
    pricing_data; categories WITHOUT service data keep their original
    template rows (the lawyer's rows) untouched.
    """
    rows = _get_rows(tbl)
    if len(rows) < 4:
        return tbl

    title_row  = rows[0]  # "XİDMƏTLƏRİN HƏCMİ"
    header_row = rows[1]  # column headers

    # Parse template into per-category sections
    tpl_sections = _parse_template_sections(rows[2:])

    # Find a service-row template (8 cells) for rebuilding
    svc_tpl = None
    subtotal_tpl = None
    for sec in tpl_sections:
        for r in sec['services']:
            cells = _get_cells(r)
            if len(cells) == 8 and svc_tpl is None:
                svc_tpl = r
            if svc_tpl:
                break
        if sec['subtotal'] and subtotal_tpl is None:
            subtotal_tpl = sec['subtotal']
        if svc_tpl and subtotal_tpl:
            break
    cat_hdr_tpl = tpl_sections[0]['header'] if tpl_sections else None

    # Build display→short reverse map and short→display forward map
    display_to_short = {v: k for k, v in CAT_FULL_NAMES.items()}
    # Also NFC-normalize for robust matching
    import unicodedata
    def _n(s):
        return unicodedata.normalize("NFC", s).upper()
    # Build lookup: NFC-upper display_name → template section
    tpl_by_name = {}
    for sec in tpl_sections:
        tpl_by_name[_n(sec['display_name'])] = sec

    def _strip_punct(s):
        """Remove punctuation and extra spaces for fuzzy matching."""
        return re.sub(r'[^A-ZÀ-ÖØ-Ýİ0-9 ]', '', s).strip()

    def _find_tpl_section(display_name):
        """Find template section by exact match, then fuzzy (partial) match."""
        key = _n(display_name)
        # Exact match
        if key in tpl_by_name:
            return tpl_by_name[key]
        # Fuzzy match: strip punctuation, compare first significant prefix
        key_clean = _strip_punct(key)
        for tpl_key, sec in tpl_by_name.items():
            tpl_clean = _strip_punct(tpl_key)
            # Match if first 6 chars of cleaned versions overlap
            if len(key_clean) >= 6 and len(tpl_clean) >= 6:
                if key_clean[:6] == tpl_clean[:6]:
                    return sec
        return None

    new_rows = [title_row, header_row]
    global_svc_idx = 1

    for cat_display, cat_total in non_zero_cats:
        short_key = display_to_short.get(cat_display, cat_display)
        cat_data  = pricing_cats.get(short_key, {})
        services  = [s for s in cat_data.get("services", []) if s.get("total", 0) > 0]

        # Look up original template section for this category
        tpl_sec = _find_tpl_section(cat_display)

        if services:
            # ── HAS service data → rebuild from pricing_data ──
            if cat_hdr_tpl:
                new_rows.append(_ensure_keep_next(
                    _clone_row_with_values(cat_hdr_tpl, [cat_display])))

            for svc in services:
                req_type = svc.get("mandatory", "Mandatory")
                mode     = svc.get("mode", "8/5")
                new_rows.append(_clone_row_with_values(svc_tpl, [
                    str(global_svc_idx),
                    svc.get("name", ""),
                    req_type,
                    svc.get("unit", ""),
                    mode,
                    str(int(svc.get("qty", 0))),
                    _fmt_bare(svc.get("price", 0)),
                    f" {_fmt(svc.get('total', 0))} ",
                ]))
                global_svc_idx += 1

            if subtotal_tpl:
                new_rows.append(_clone_row_with_values(subtotal_tpl, ["Cəmi", _fmt(cat_total)]))

        elif tpl_sec:
            # ── NO service data but template section exists → KEEP original rows ──
            # keepNext on header so it stays with first service row
            new_rows.append(_ensure_keep_next(tpl_sec['header']))
            for sr in tpl_sec['services']:
                new_rows.append(sr)
                global_svc_idx += 1
            # Update subtotal with current total from pricing_data
            if tpl_sec['subtotal'] and subtotal_tpl:
                new_rows.append(_clone_row_with_values(
                    tpl_sec['subtotal'], ["Cəmi", _fmt(cat_total)]
                ))
            elif tpl_sec['subtotal']:
                new_rows.append(tpl_sec['subtotal'])

        else:
            # ── NO service data AND no template section → just header + subtotal ──
            if cat_hdr_tpl:
                new_rows.append(_ensure_keep_next(
                    _clone_row_with_values(cat_hdr_tpl, [cat_display])))
            if subtotal_tpl:
                new_rows.append(_clone_row_with_values(subtotal_tpl, ["Cəmi", _fmt(cat_total)]))

    # Rebuild table XML
    tbl_start = re.match(r"(<w:tbl\b[^>]*>(?:.*?<w:tblPr>.*?</w:tblPr>)?(?:.*?<w:tblGrid>.*?</w:tblGrid>)?)", tbl, re.DOTALL)
    tbl_header = tbl_start.group(1) if tbl_start else "<w:tbl>"
    return tbl_header + "".join(new_rows) + "</w:tbl>"


def update_requisites_table(tbl: str, details: dict) -> str:
    """
    Update Table 3 (requisites side-by-side).
    Only replace client-specific values; Guven's column stays untouched.
    """
    c = details.get("client", {})
    rows = _get_rows(tbl)
    if len(rows) < 3:
        return tbl

    # Row 1: company names  — replace client name
    row1_cells = _get_cells(rows[1])
    if len(row1_cells) >= 2:
        new_client_name_cell = _replace_cell_text(
            row1_cells[1],
            f'"{c.get("legal_name","")}" {_get_org_suffix(c.get("legal_name",""))}'
        )
        rows[1] = rows[1].replace(row1_cells[1], new_client_name_cell, 1)

    # Row 2: full requisites text — do text substitutions
    # We let _replace_variables handle this via the main xml replacement
    # (already done before calling this function)

    tbl_start = re.match(r"(<w:tbl\b[^>]*>(?:.*?<w:tblPr>.*?</w:tblPr>)?(?:.*?<w:tblGrid>.*?</w:tblGrid>)?)", tbl, re.DOTALL)
    tbl_header = tbl_start.group(1) if tbl_start else "<w:tbl>"
    return tbl_header + "".join(rows) + "</w:tbl>"


def _get_org_suffix(name: str) -> str:
    """Detect legal form from name."""
    for suffix in ("MMC", "ASC", "SC", "QSC", "İB"):
        if suffix in name.upper():
            return suffix
    return "MMC"


# ── main generation function ──────────────────────────────────────────────────

def generate_contract(
    company_code: str,
    params=None,
    pricing_override=None,
) -> str:
    """
    Generate a filled contract .docx for company_code.
    params may contain: annex_number, contract_number, signing_date,
                        period_start, period_end
    pricing_override: optional dict with same structure as a company entry
                      in pricing_data.json (with 'categories' key).
                      If provided, uses these prices instead of pricing_data.json.
    Returns the path to the generated file.
    """
    params = params or {}

    # 1. Load data
    pricing_data = _load_json(PRICING_FILE)
    all_details  = _load_json(DETAILS_FILE)

    # Find company in pricing_data (NFC-normalized, case-insensitive)
    # Needed because JSON keys may store İ as decomposed (I + combining dot) vs precomposed
    pricing_key = next(
        (k for k in pricing_data if _nfc(k) == _nfc(company_code)), None
    )
    if not pricing_key:
        # Try partial match
        pricing_key = next(
            (k for k in pricing_data if _nfc(company_code) in _nfc(k) or _nfc(k) in _nfc(company_code)),
            None
        )
    if not pricing_key:
        raise ValueError(f"Company '{company_code}' not found in pricing_data.json")

    company_pricing = pricing_override if pricing_override else pricing_data[pricing_key]
    categories = company_pricing.get("categories", {})

    # Non-zero categories (for summary table)
    non_zero_cats = [
        (CAT_FULL_NAMES.get(k, k), v["total"])
        for k, v in categories.items()
        if v.get("total", 0) > 0
    ]

    # Company details (for variable substitution)
    details = all_details.get(company_code) or all_details.get(pricing_key) or {}

    # 2. Find template — whitelist sanitization
    safe_code = re.sub(r'[^a-zA-Z0-9\u00C0-\u024F\u0400-\u04FF _\-]', '_', company_code)
    safe_code = safe_code.replace('..', '').strip()[:100]
    tpl_path  = os.path.join(TEMPLATES_DIR, f"{safe_code}.docx")
    if not os.path.exists(tpl_path):
        # Try pricing_key name
        tpl_path = os.path.join(TEMPLATES_DIR, f"{pricing_key}.docx")
    if not os.path.exists(tpl_path):
        tpl_path = os.path.join(TEMPLATES_DIR, FALLBACK_TEMPLATE)
    if not os.path.exists(tpl_path):
        raise FileNotFoundError(f"No template found for {company_code}")

    # 3. Read all zip parts
    parts = _read_all_parts(tpl_path)

    # 4. Get and merge-runs document XML
    xml = parts["word/document.xml"].decode("utf-8")
    xml = _merge_runs(xml)

    # 5. Replace text variables
    xml = _replace_variables(xml, details, params)

    # 5b. Fallback template: replace remaining AZMADE references
    if tpl_path.endswith(FALLBACK_TEMPLATE) or "AZMADE" in os.path.basename(tpl_path).upper():
        _client = details.get("client", {})
        _new_legal = _esc_xml(_client.get("legal_name", "") or company_code)
        import re as _re
        # Replace "AZMADE GROUP" with any whitespace between words
        xml = _re.sub(r"AZMADE\s+GROUP", _new_legal, xml)
        # Replace standalone AZMADE (in contract numbers like GT/AZMADE/...)
        xml = xml.replace("AZMADE", _esc_xml(company_code))


    # 6. Rebuild tables
    # Check if individual service data exists (qty/total set per service)
    has_service_data = any(
        s.get("total", 0) > 0
        for cat in categories.values()
        for s in cat.get("services", [])
    )

    tables_in_xml = _get_tables(xml)
    if len(tables_in_xml) >= 2:
        # Table 0 → always rebuild summary (category totals)
        new_tbl0 = rebuild_summary_table(tables_in_xml[0], non_zero_cats)
        xml = xml.replace(tables_in_xml[0], new_tbl0, 1)

        # Table 1 → rebuild detail only if individual service data exists
        # Otherwise keep template rows (they contain the correct service breakdown)
        if has_service_data:
            tables_in_xml = _get_tables(xml)   # re-fetch after tbl0 replacement
            new_tbl1 = rebuild_detail_table(tables_in_xml[1], non_zero_cats, categories)
            xml = xml.replace(tables_in_xml[1], new_tbl1, 1)

    # 7. Write output — sanitize filename to prevent path traversal
    import re as _re
    safe_code = _re.sub(r'[^a-zA-Z0-9\u00C0-\u024F\u0400-\u04FF _\-]', '_', company_code)
    safe_code = safe_code.replace('..', '').strip()[:100]
    annex_no  = params.get("annex_number", details.get("annex_number", ""))
    fname     = f"{safe_code} - Guven Technology - Əlavə №{annex_no} - Xidmətlərin həcmi və qiymət cədvəli.docx"
    out_path  = os.path.join(OUTPUT_DIR, fname)
    # Verify resolved path is within OUTPUT_DIR
    if not os.path.realpath(out_path).startswith(os.path.realpath(OUTPUT_DIR)):
        raise ValueError("Invalid company code: path traversal detected")
    _write_docx(parts, xml, out_path)
    return out_path


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 generate_contract.py <company_code> [annex_number] [signing_date]")
        sys.exit(1)

    code   = sys.argv[1]
    params = {}
    if len(sys.argv) > 2:
        params["annex_number"] = sys.argv[2]
    if len(sys.argv) > 3:
        params["signing_date"] = sys.argv[3]

    try:
        path = generate_contract(code, params)
        print(f"Generated: {path}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback; traceback.print_exc()
