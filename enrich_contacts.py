"""
Enrich Contacts — Extract data from email signatures
=====================================================
Scans Apple Mail .emlx files, finds email signatures for each sender,
extracts phone, role/title, company name, address, and updates CRM contacts.
"""

import email
import re
import os
import logging
import pathlib
from email.header import decode_header
from email.utils import parseaddr
from typing import Dict, Optional, List, Tuple

from dotenv import load_dotenv
load_dotenv()

from database import init_db, get_db
from models import Contact, Company

logger = logging.getLogger(__name__)

APPLE_MAIL_PATH = os.getenv(
    "APPLE_MAIL_PATH",
    os.path.expanduser("~/Library/Mail/V10")
)

OWN_DOMAIN = ""
_email_addr = os.getenv("EMAIL_ADDRESS", "")
if "@" in _email_addr:
    OWN_DOMAIN = _email_addr.split("@")[1].lower()


# ─── Helpers ─────────────────────────────────────────────────

def _decode_header_value(raw):
    if not raw:
        return ""
    parts = decode_header(raw)
    result = []
    for part, enc in parts:
        if isinstance(part, bytes):
            result.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            result.append(str(part))
    return "".join(result)


def _get_text_body(msg):
    """Extract plain text body from email."""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if ct == "text/plain" and "attachment" not in disp:
                try:
                    charset = part.get_content_charset() or "utf-8"
                    return part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            return msg.get_payload(decode=True).decode(charset, errors="replace")
        except Exception:
            pass
    return ""


def _parse_emlx(file_path):
    """Parse an Apple Mail .emlx file."""
    try:
        with open(file_path, "rb") as f:
            first_line = f.readline()
            try:
                byte_count = int(first_line.strip())
                raw_email = f.read(byte_count)
            except (ValueError, TypeError):
                f.seek(0)
                raw_email = f.read()
            return email.message_from_bytes(raw_email)
    except Exception:
        return None


# ─── Signature extraction ────────────────────────────────────

# Phone patterns — require prefix or + to avoid matching dates
PHONE_RE = re.compile(
    r'(?:'
    r'(?:Mob|Tel|Cell|Phone|Mobile|Fax|Тел|Моб)[.\s:]*(\+?\d[\d\s\-().]{7,20}\d)'
    r'|'
    r'(\+\d[\d\s\-().]{7,20}\d)'  # International format with +
    r')',
    re.IGNORECASE
)

# Role/title patterns — match "Title | Company" or "Title, Company" lines
ROLE_PATTERNS = [
    # "Account Manager | GT LLC"
    re.compile(r'^([A-Za-zА-Яа-яÖöÜüŞşĞğÇçƏəİı\s,&]+(?:Manager|Director|Specialist|Engineer|Officer|Head|Lead|Coordinator|Consultant|Administrator|Analyst|Developer|Architect|Assistant|Executive|Partner|President|CEO|CTO|CFO|CIO|COO|VP|SVP|AVP)[\w\s,]*?)(?:\s*[|,]\s*(.+))?$', re.IGNORECASE),
    # "IT Specialist" standalone
    re.compile(r'^((?:Senior |Junior |Lead |Chief |Deputy |Head of )?(?:IT|HR|PR|QA|Sales|Finance|Marketing|Legal|Operations|Business|Account|Project|Product|Change Management|Communication|Information|Network|System|Software|Hardware|Security|Data|Cloud|DevOps|Infrastructure|Technical|Procurement|Supply Chain|Logistics)[\w\s,&]*(?:Manager|Director|Specialist|Engineer|Officer|Head|Lead|Coordinator|Consultant|Administrator|Analyst|Developer|Architect|Assistant|Executive|Partner|Supervisor|Representative)[\w\s]*)$', re.IGNORECASE),
]

# Common separator patterns between body and signature
SIG_SEPARATORS = [
    r'(?:^|\n)[-–—_]{2,}',
    r'(?:^|\n)(?:Hörmətlə|Best [Rr]egards|Kind [Rr]egards|Regards|С уважением|Təşəkkür|Thanks)',
    r'(?:^|\n)Sent from',
]
SIG_SEP_RE = re.compile('|'.join(SIG_SEPARATORS), re.MULTILINE)


def _extract_signature_block(body):
    """Try to extract signature block from email body."""
    if not body:
        return ""

    lines = body.strip().split('\n')

    # Method 1: Look for separator, take everything after last occurrence
    matches = list(SIG_SEP_RE.finditer(body))
    if matches:
        last_match = matches[-1]
        sig_text = body[last_match.start():]
        sig_lines = sig_text.strip().split('\n')
        # Signature shouldn't be too long (max ~20 lines)
        if len(sig_lines) <= 25:
            return sig_text.strip()

    # Method 2: Take last 15 lines
    if len(lines) > 5:
        return '\n'.join(lines[-15:])

    return ""


def _extract_phones(text):
    """Extract phone numbers from text."""
    phones = []
    for match in PHONE_RE.finditer(text):
        # Get whichever group matched
        phone = (match.group(1) or match.group(2) or "").strip()
        if not phone:
            continue
        # Clean up
        digits = re.sub(r'[^\d+]', '', phone)
        if len(digits) >= 8:  # Valid phone has at least 8 digits
            # Skip if it looks like a date (e.g., 2026-03-04)
            if re.match(r'20\d{2}', digits):
                continue
            phones.append(phone)
    return phones


def _extract_role(text):
    """Extract job title/role from signature text."""
    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line or len(line) > 100:
            continue
        # Clean markdown/URL artifacts
        line = re.sub(r'\[.*?\]', '', line)
        line = re.sub(r'<.*?>', '', line)
        line = re.sub(r'https?://\S+', '', line)
        line = line.strip()
        if not line:
            continue
        for pattern in ROLE_PATTERNS:
            m = pattern.match(line)
            if m:
                role = m.group(1).strip().rstrip('|,')
                return role
    return ""


def _extract_company_from_sig(text):
    """Extract company name from signature if mentioned after | or on a dedicated line."""
    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        # "Title | Company Name" pattern
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 2:
                company = parts[-1].strip()
                # Clean artifacts
                company = re.sub(r'\[.*?\]', '', company).strip()
                company = re.sub(r'<.*?>', '', company).strip()
                if company and len(company) > 2 and len(company) < 60:
                    # Skip if it looks like a phone or email
                    if '@' not in company and not re.match(r'^[\d\s+()-]+$', company):
                        return company
    return ""


def _extract_address(text):
    """Extract address from signature."""
    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        line = re.sub(r'<.*?>', '', line).strip()
        if not line or len(line) > 150:
            continue
        # Look for lines with address indicators
        if re.search(r'(?:Baku|Azerbaijan|Bakı|AZ\d{4}|street|avenue|str\.|küç|проспект|пр\.|ул\.)', line, re.IGNORECASE):
            addr = line.strip().rstrip(',')
            if len(addr) > 10:
                return addr
    return ""


# ─── Main enrichment logic ───────────────────────────────────

def collect_signatures_from_mail(mail_path=None, limit=2000):
    """Scan emails, collect best signature for each sender.

    Returns: dict of email -> {phone, role, company, address, full_name}
    """
    mail_path = mail_path or APPLE_MAIL_PATH
    mail_path = pathlib.Path(mail_path)

    if not mail_path.exists():
        logger.error("Apple Mail path not found: %s", mail_path)
        return {}

    # Find .emlx files
    emlx_files = []
    for account_dir in mail_path.iterdir():
        if not account_dir.is_dir() or account_dir.name.startswith('.'):
            continue
        _scan_for_emlx(account_dir, emlx_files, depth=0)

    logger.info("Found %d .emlx files to scan", len(emlx_files))
    emlx_files = emlx_files[:limit]

    # Collect signatures per sender
    sender_data = {}  # email -> list of extracted data dicts

    for i, fp in enumerate(emlx_files):
        msg = _parse_emlx(fp)
        if not msg:
            continue

        from_raw = _decode_header_value(msg.get("From", ""))
        name, addr = parseaddr(from_raw)
        addr = addr.strip().lower()

        if not addr or '@' not in addr:
            continue

        # Skip own domain
        domain = addr.split('@')[1]
        if OWN_DOMAIN and domain == OWN_DOMAIN:
            continue

        body = _get_text_body(msg)
        if not body or len(body) < 30:
            continue

        sig = _extract_signature_block(body)
        if not sig:
            continue

        phones = _extract_phones(sig)
        role = _extract_role(sig)
        company = _extract_company_from_sig(sig)
        address = _extract_address(sig)

        # Only store if we found something useful
        if phones or role or company or address:
            if addr not in sender_data:
                sender_data[addr] = {
                    "email": addr,
                    "name": _decode_header_value(name) if name else "",
                    "phones": [],
                    "roles": [],
                    "companies": [],
                    "addresses": [],
                }
            data = sender_data[addr]
            if phones:
                data["phones"].extend(phones)
            if role:
                data["roles"].append(role)
            if company:
                data["companies"].append(company)
            if address:
                data["addresses"].append(address)

        if (i + 1) % 200 == 0:
            logger.info("Scanned %d/%d emails, found data for %d senders",
                        i + 1, len(emlx_files), len(sender_data))

    # Deduplicate and pick best values
    result = {}
    for addr, data in sender_data.items():
        best = {
            "email": addr,
            "name": data["name"],
            "phone": _most_common(data["phones"]) or "",
            "role": _most_common(data["roles"]) or "",
            "company_name": _most_common(data["companies"]) or "",
            "address": _most_common(data["addresses"]) or "",
        }
        result[addr] = best

    logger.info("Extracted signature data for %d contacts", len(result))
    return result


def _most_common(lst):
    """Return most common item from list, or empty string."""
    if not lst:
        return ""
    # Count occurrences
    counts = {}
    for item in lst:
        item = item.strip()
        if item:
            counts[item] = counts.get(item, 0) + 1
    if not counts:
        return ""
    return max(counts, key=counts.get)


def _scan_for_emlx(path, result_list, depth=0):
    """Recursively scan for .emlx files."""
    if depth > 10:
        return
    try:
        entries = list(path.iterdir())
    except (PermissionError, OSError):
        return
    for entry in entries:
        if entry.is_file() and entry.suffix == ".emlx" and ".partial." not in entry.name:
            result_list.append(entry)
        elif entry.is_dir():
            name = entry.name
            if name.startswith(".") or name == "Attachments":
                continue
            _scan_for_emlx(entry, result_list, depth + 1)


def enrich_contacts(mail_path=None, dry_run=False, limit_override=None):
    """Main function: scan emails, extract signatures, update CRM contacts.

    Args:
        mail_path: Path to Apple Mail V10 directory
        dry_run: If True, only show what would be updated without making changes
        limit_override: Override default limit of 2000 emails to scan

    Returns: dict with stats
    """
    init_db()

    stats = {
        "contacts_checked": 0,
        "contacts_enriched": 0,
        "phones_added": 0,
        "roles_added": 0,
        "companies_updated": 0,
        "skipped_no_data": 0,
    }

    # Step 1: Collect signature data
    scan_limit = limit_override or 2000
    logger.info("Step 1: Scanning emails for signatures (limit=%d)...", scan_limit)
    sig_data = collect_signatures_from_mail(mail_path, limit=scan_limit)

    if not sig_data:
        logger.warning("No signature data found")
        return stats

    # Step 2: Get all contacts from CRM
    logger.info("Step 2: Updating contacts in CRM...")
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM contacts").fetchall()
        contacts = [dict(r) for r in rows]

    logger.info("Found %d contacts in CRM", len(contacts))

    for contact in contacts:
        stats["contacts_checked"] += 1
        email_addr = contact["email"].lower()

        if email_addr not in sig_data:
            stats["skipped_no_data"] += 1
            continue

        sig = sig_data[email_addr]
        updates = {}

        # Fill in missing phone
        if sig["phone"] and not contact.get("phone"):
            updates["phone"] = sig["phone"]
            stats["phones_added"] += 1

        # Fill in missing role
        if sig["role"] and not contact.get("role"):
            updates["role"] = sig["role"]
            stats["roles_added"] += 1

        # Update company name if better info available
        if sig["company_name"] and (not contact.get("company_name") or
                contact["company_name"] == contact["email"].split("@")[1].split(".")[0].capitalize()):
            updates["company_name"] = sig["company_name"]
            stats["companies_updated"] += 1

        # Add address to notes if we have it
        if sig["address"] and not contact.get("notes"):
            updates["notes"] = "Address: %s" % sig["address"]

        if updates:
            if dry_run:
                logger.info(
                    "  [DRY RUN] Would update %s: %s",
                    email_addr, updates
                )
            else:
                Contact.update(contact["id"], updates)
                logger.info("  Updated %s: %s", email_addr, list(updates.keys()))
            stats["contacts_enriched"] += 1

    return stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    init_db()
    print("Enriching contacts from email signatures...")
    print()
    result = enrich_contacts()
    print()
    print("=== Results ===")
    for k, v in result.items():
        print("  %s: %s" % (k, v))
