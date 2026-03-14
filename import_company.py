"""
Import company pricing data from Excel calculator files.
Parses the standard Guven Technology tariff calculator format.
Automatically filters out junk rows — only the 11 valid categories are kept.
"""

import json
import os
import re
import unicodedata
import openpyxl


def norm(s):
    """Normalize Unicode (NFC) and strip whitespace."""
    return unicodedata.normalize('NFC', s.strip()) if s else ''

def norm_svc_name(s):
    """Normalize service name: strip trailing markers, parenthetical content, and extra whitespace."""
    if not s:
        return s
    # Strip trailing TEMP/OLD markers
    s = re.sub(r'\s+TEMP\s*$', '', s, flags=re.IGNORECASE)
    # Strip ALL trailing parenthetical content e.g. (Yeni xidmetdir), (Account Management Service OLD)
    s = re.sub(r'\s*\([^)]*\)\s*$', '', s)
    # Apply again for nested cases like (xxx) TEMP
    s = re.sub(r'\s+TEMP\s*$', '', s, flags=re.IGNORECASE)
    s = re.sub(r'\s*\([^)]*\)\s*$', '', s)
    # Remove trailing patterns like (7), (10), (210)
    s = re.sub(r'\s*\(\d+\)\s*$', '', s)
    # Normalize quotes: replace smart quotes with regular ones
    s = s.replace('“', '"').replace('”', '"')
    # Normalize dashes
    s = s.replace('–', '-').replace('—', '-')
    s = re.sub(r'\s*-\s*', '-', s)
    # Collapse multiple spaces
    s = re.sub(r'\s+', ' ', s).strip()
    return s


# ── Whitelist: ONLY these 11 categories are valid ────────────
# Map full Excel names → short keys used in pricing_data.json
CATEGORY_FULL_TO_SHORT = {
    "İT İnfrastruktur və Server Xidmətləri": "İT İnfrastruktur",
    "Məlumat Bazası və Məlumat İdarəetmə": "Məlumat Bazası",
    "Bulud Xidmətləri və 'as-a-Service' Platformaları": "Bulud Xidmətləri",
    "Avtomatlaşdırılmış Sistemlər və Biznes Proqramları": "Avtomatlaşdırılmış Sistemlər",
    "SaaS Biznes Process Modulu (Opsional - Project Base)": "SaaS Biznes Process",
    "Video, Monitorinq və Giriş-Çıxışa Nəzarət Sistemləri": "Video, Monitorinq",
    "İnformasiya Təhlükəsizlik Xidmətləri": "İnformasiya Təhlükəsizlik",
    "Konsaltinq və Layihə İdarəetməsi": "Konsaltinq və Layihə",
    "Audit və Uyğunluq Xidmətləri": "Audit və Uyğunluq",
    "Təlim və Maarifləndirmə": "Təlim və Maarifləndirmə",
    "HelpDesk və Texniki Dəstək Xidmətləri": "HelpDesk və Texniki Dəstək",
}

# The 11 valid short-key category names
VALID_CATEGORIES = set(CATEGORY_FULL_TO_SHORT.values())


def _is_valid_category_header(text):
    """Check if text matches a valid category header (full or short name)."""
    normalized = norm(text)
    # Check exact match against full names
    if normalized in CATEGORY_FULL_TO_SHORT:
        return CATEGORY_FULL_TO_SHORT[normalized]
    # Check exact match against short names
    if normalized in VALID_CATEGORIES:
        return normalized
    return None


def _looks_like_summary_row(c3_val, c4_val):
    """
    Detect rows from the summary table at the bottom of the file
    (e.g. R124: "İT XİDMƏTLƏRİN ADI" / "DƏYƏRİ NET", or R136: "TOPLAM AYLIQ").
    These rows have C3=category name and C4=number, but no C6/C7 service data.
    """
    if not c3_val:
        return False
    s = norm(str(c3_val)).upper()
    # Known summary labels
    junk_patterns = [
        "TOPLAM", "İT XİDMƏTLƏRİN", "İT XIDMƏTLƏRİN",
        "DƏYƏRİ", "AÇIQLAMA", "İT XİDMƏTLƏR",
    ]
    for p in junk_patterns:
        if p in s:
            return True
    return False


def parse_calculator_sheet(filepath):
    """
    Parse a Guven Technology calculator Excel file.
    Only extracts the 11 valid service categories — everything else is discarded.
    Returns dict: {categories: {cat: {total, services: [...]}}, monthly, annual}
    """
    wb = openpyxl.load_workbook(filepath, data_only=True)
    # Also open without data_only to detect formula cells (for fallback)
    wb_formulas = openpyxl.load_workbook(filepath, data_only=False)

    # Try 'Calculator' sheet first, fall back to first sheet
    if 'Calculator' in wb.sheetnames:
        ws = wb['Calculator']
    else:
        ws = wb[wb.sheetnames[0]]

    categories = {}
    current_cat = None  # None means "we're in a junk/unknown section, skip services"

    for r in range(1, ws.max_row + 1):
        c1 = ws.cell(r, 1).value
        c2 = ws.cell(r, 2).value
        c3 = ws.cell(r, 3).value
        c4 = ws.cell(r, 4).value  # unit / or summary value
        c5 = ws.cell(r, 5).value  # required
        c6 = ws.cell(r, 6).value  # qty
        c7 = ws.cell(r, 7).value  # price
        c9 = ws.cell(r, 9).value  # total (DƏYƏRİ NET)

        # Skip completely empty rows
        if all(v is None for v in [c1, c2, c3, c4, c6, c7, c9]):
            continue

        # Skip known summary/junk rows (bottom of file)
        if _looks_like_summary_row(c3, c4) and c2 is None and c6 is None:
            current_cat = None
            continue

        # ── Detect category header ───────────────────────
        # Category headers: C3 has text, C2 is empty, no C6/C7
        if c3 and c2 is None and c6 is None and c7 is None and r > 2:
            cat_key = _is_valid_category_header(str(c3))
            if cat_key:
                current_cat = cat_key
                if current_cat not in categories:
                    categories[current_cat] = {"total": 0, "services": []}
            else:
                # Not a valid category — could be junk header like
                # "İT ÜZRƏ SAAS XİDMƏTLƏR", "TELEKOMUNİKASİYA XİDMƏTLƏRİ" etc.
                # DON'T set current_cat = None here, because these sub-headers
                # appear INSIDE valid categories (e.g. row labels inside
                # Avtomatlaşdırılmış Sistemlər). Keep current_cat unchanged.
                pass
            continue

        # ── Detect "Toplam" subtotal row ─────────────────
        if c2 is not None and str(c2).strip() == "Toplam":
            if current_cat and current_cat in categories and c9 is not None:
                categories[current_cat]["total"] = round(float(c9 or 0), 2)
            continue

        # ── Detect service row ───────────────────────────
        # Service rows: C2=number, C3=name, C7=price
        if c2 is not None and c3 is not None and c7 is not None and current_cat:
            try:
                int(c2)  # must be a service index number
            except (ValueError, TypeError):
                continue

            svc_name = norm_svc_name(norm(str(c3)))
            unit = norm(str(c4)) if c4 else ""
            qty = float(c6) if c6 is not None else 0
            price = float(c7) if c7 is not None else 0
            # Get c9 from data_only sheet; if None, check formula sheet for cached value
            if c9 is None:
                # Check if formula sheet has a formula in column I
                fc9 = ws_formulas.cell(row=row[0].row, column=9).value
                if fc9 is not None and isinstance(fc9, str) and fc9.startswith('='):
                    # Formula exists but no cached value - total unknown, use qty*price
                    total = round(qty * price, 2)
                else:
                    # Not a formula, genuinely empty - use qty*price
                    total = round(qty * price, 2)
            else:
                total = round(float(c9), 2)
            # Use effective price when Excel formula total differs from qty*price
            if qty > 0 and total > 0 and abs(total - qty * price) > 0.01:
                price = round(total / qty, 2)

            categories[current_cat]["services"].append({
                "name": svc_name,
                "qty": qty,
                "price": price,
                "total": total,
                "unit": unit
            })

    # ── Final cleanup: keep ONLY valid categories ────────
    categories = {k: v for k, v in categories.items() if k in VALID_CATEGORIES}

    # ── Deduplicate services within each category ──────
    # Excel files sometimes have repeated sections; keep the entry with higher value
    for cat, data in categories.items():
        svcs = data.get("services", [])
        if not svcs:
            continue
        seen = {}
        unique = []
        for svc in svcs:
            name = svc.get("name", "").strip()
            if name in seen:
                existing = seen[name]
                existing_val = existing.get("total", 0) or (existing.get("qty", 0) * existing.get("price", 0))
                new_val = svc.get("total", 0) or (svc.get("qty", 0) * svc.get("price", 0))
                if new_val > existing_val:
                    idx = next(i for i, s in enumerate(unique) if s.get("name", "").strip() == name)
                    unique[idx] = svc
                    seen[name] = svc
            else:
                seen[name] = svc
                unique.append(svc)
        data["services"] = unique

    # Recalculate totals from services (services are ground truth)
    for cat, data in categories.items():
        if data["services"]:
            data["total"] = round(sum(s["total"] for s in data["services"]), 2)

    monthly = round(sum(d["total"] for d in categories.values()), 2)
    annual = round(monthly * 12, 2)

    return {
        "categories": categories,
        "monthly": monthly,
        "annual": annual
    }


def import_company(filepath, company_name, group_name, legal_name=None):
    """
    Import a company from an Excel calculator file into pricing_data.json.

    Args:
        filepath: Path to the .xlsx file
        company_name: Short name (e.g. "AGF")
        group_name: Group assignment (e.g. "Separated", "Tabia", etc.)
        legal_name: Optional full legal name

    Returns:
        dict with keys: success, message, company_name, monthly, annual, categories_count, services_count
    """
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    pricing_path = os.path.join(static_dir, "pricing_data.json")
    legal_path = os.path.join(static_dir, "company_legal_names.json")

    # Parse Excel
    parsed = parse_calculator_sheet(filepath)
    if not parsed["categories"]:
        return {"success": False, "message": "No categories found in the file. Make sure it follows the standard calculator format."}

    # Ensure all 11 standard categories exist
    with open(pricing_path, "r", encoding="utf-8") as f:
        pricing = json.load(f)

    # Ensure all 11 standard categories exist (even if this is the first import)
    if pricing:
        ref_company = list(pricing.keys())[0]
        ref_cats = set(pricing[ref_company]["categories"].keys())
    else:
        ref_cats = VALID_CATEGORIES  # Use whitelist when no reference company exists

    for cat in ref_cats:
        if cat not in parsed["categories"]:
            parsed["categories"][cat] = {"total": 0, "services": []}

    # Build entry
    entry = {
        "group": group_name,
        "categories": parsed["categories"],
        "monthly": parsed["monthly"],
        "annual": parsed["annual"]
    }

    # Save to pricing_data
    pricing[company_name] = entry
    with open(pricing_path, "w", encoding="utf-8") as f:
        json.dump(pricing, f, ensure_ascii=False, indent=2)

    # Save legal name if provided
    if legal_name:
        try:
            with open(legal_path, "r", encoding="utf-8") as f:
                legal = json.load(f)
        except FileNotFoundError:
            legal = {}
        legal[company_name] = legal_name
        with open(legal_path, "w", encoding="utf-8") as f:
            json.dump(legal, f, ensure_ascii=False, indent=2)

    services_count = sum(len(d["services"]) for d in parsed["categories"].values())

    return {
        "success": True,
        "message": f"Company '{company_name}' imported successfully",
        "company_name": company_name,
        "group": group_name,
        "monthly": parsed["monthly"],
        "annual": parsed["annual"],
        "categories_count": len(parsed["categories"]),
        "services_count": services_count
    }
