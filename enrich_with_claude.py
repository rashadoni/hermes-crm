"""
Enrich Contacts via Claude Sonnet
===================================
For contacts without phone/role, finds their emails, sends text
to Claude API in batches, extracts structured contact info.
"""

import os
import json
import logging
import pathlib
import email
import time
from email.header import decode_header
from email.utils import parseaddr
from typing import Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

import anthropic

from database import init_db, get_db
from models import Contact

logger = logging.getLogger(__name__)

APPLE_MAIL_PATH = os.getenv(
    "APPLE_MAIL_PATH",
    os.path.expanduser("~/Library/Mail/V10")
)
OWN_DOMAIN = ""
_own = os.getenv("EMAIL_ADDRESS", "")
if "@" in _own:
    OWN_DOMAIN = _own.split("@")[1].lower()

MODEL = os.getenv("ENRICH_MODEL", "claude-haiku-4-5-20251001")

def _get_client():
    """Lazy init of Anthropic client so env vars are loaded first."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set in .env")
    return anthropic.Anthropic(api_key=api_key)


# ─── Helpers ─────────────────────────────────────────────────

def _decode_hdr(raw):
    if not raw:
        return ""
    parts = decode_header(raw)
    out = []
    for p, enc in parts:
        if isinstance(p, bytes):
            out.append(p.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(str(p))
    return "".join(out)


def _strip_html(html):
    """Strip HTML tags and decode entities to plain text."""
    import re
    html = re.sub(r'<br\s*/?>', '\n', html, flags=re.IGNORECASE)
    html = re.sub(r'<p[^>]*>', '\n', html, flags=re.IGNORECASE)
    html = re.sub(r'<[^>]+>', '', html)
    html = html.replace('&nbsp;', ' ').replace('&amp;', '&')
    html = html.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
    html = re.sub(r'\n{3,}', '\n\n', html)
    return html.strip()


def _get_text(msg):
    """Extract plain text from email, falling back to stripped HTML."""
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            try:
                cs = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                text = payload.decode(cs, errors="replace")
                if ct == "text/plain" and not plain:
                    plain = text
                elif ct == "text/html" and not html:
                    html = text
            except Exception:
                pass
    else:
        try:
            cs = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(cs, errors="replace")
                if msg.get_content_type() == "text/html":
                    html = text
                else:
                    plain = text
        except Exception:
            pass

    if plain:
        return plain
    if html:
        return _strip_html(html)
    return ""


def _parse_emlx(fp):
    try:
        with open(fp, "rb") as f:
            first = f.readline()
            try:
                n = int(first.strip())
                raw = f.read(n)
            except (ValueError, TypeError):
                f.seek(0)
                raw = f.read()
            return email.message_from_bytes(raw)
    except Exception:
        return None


def _scan_emlx(mail_path):
    """Collect all .emlx files."""
    result = []
    mail_path = pathlib.Path(mail_path)

    def _walk(path, depth=0):
        if depth > 10:
            return
        try:
            for entry in path.iterdir():
                if entry.is_file() and entry.suffix == ".emlx" :
                    result.append(entry)
                elif entry.is_dir() and not entry.name.startswith(".") and entry.name != "Attachments":
                    _walk(entry, depth + 1)
        except (PermissionError, OSError):
            pass

    for d in mail_path.iterdir():
        if d.is_dir() and not d.name.startswith("."):
            _walk(d)
    return result


# ─── Build email index per sender ────────────────────────────

def build_email_index(mail_path, target_emails):
    """Find best email body (with signature) for each target email address."""
    logger.info("Scanning .emlx files for %d contacts...", len(target_emails))
    files = _scan_emlx(mail_path)
    logger.info("Found %d .emlx files", len(files))

    # Sort by number descending (newest first)
    def _key(p):
        try:
            return int(p.stem.split(".")[0])
        except (ValueError, IndexError):
            return 0
    files.sort(key=_key, reverse=True)

    index = {}  # email -> best body text

    for fp in files:
        # Stop if we have good data for all targets
        if all(len(v) > 100 for v in index.values()) and \
           len(index) >= len(target_emails):
            break

        msg = _parse_emlx(fp)
        if not msg:
            continue

        from_raw = _decode_hdr(msg.get("From", ""))
        _, addr = parseaddr(from_raw)
        addr = addr.strip().lower()

        if addr not in target_emails:
            continue

        body = _get_text(msg)
        if not body:
            continue

        # Keep the longest body per contact (most likely to have signature)
        existing = index.get(addr, "")
        if len(body) > len(existing):
            index[addr] = body[:3000]  # cap at 3000 chars

    logger.info("Found email bodies for %d/%d contacts", len(index), len(target_emails))
    return index


# ─── Claude enrichment ───────────────────────────────────────

SYSTEM_PROMPT = """You are a data extraction assistant. Extract contact information from email text/signatures.
Return ONLY a valid JSON array. Each element corresponds to one contact in the batch.

For each contact return:
{
  "email": "the contact email",
  "phone": "phone number or empty string",
  "role": "job title/position or empty string",
  "company_name": "company name or empty string",
  "notes": "address or any other useful info or empty string"
}

Rules:
- Extract data ONLY from the email of the given sender (ignore quoted replies from others)
- If not found, use empty string ""
- Return ONLY the JSON array, no explanation
"""


def extract_batch(batch):
    """Send batch of {email, body} to Claude and return enriched data.

    batch: list of {"email": str, "body": str}
    Returns: list of {"email", "phone", "role", "company_name", "notes"}
    """
    # Build user message
    parts = []
    for i, item in enumerate(batch):
        # Sanitize body: ensure clean UTF-8, remove problematic characters
        body = item["body"][:1500]
        body = body.encode("utf-8", errors="replace").decode("utf-8")
        parts.append(
            "=== Contact %d: %s ===\n%s" % (i + 1, item["email"], body)
        )

    user_msg = (
        "Extract contact info for these %d people from their emails.\n\n" % len(batch)
        + "\n\n".join(parts)
    )

    try:
        client = _get_client()
        resp = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = resp.content[0].text.strip()

        # Parse JSON
        # Handle markdown code blocks if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        data = json.loads(raw)
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        logger.error("Claude API error: %s", e)
        return []


# ─── Main ────────────────────────────────────────────────────

def enrich_with_claude(mail_path=None, batch_size=10, dry_run=False):
    """
    Enrich contacts without phone/role using Claude Sonnet.

    Returns stats dict.
    """
    init_db()
    mail_path = mail_path or APPLE_MAIL_PATH

    stats = {
        "contacts_targeted": 0,
        "emails_found": 0,
        "api_calls": 0,
        "contacts_enriched": 0,
        "phones_added": 0,
        "roles_added": 0,
        "companies_updated": 0,
        "notes_added": 0,
        "input_tokens": 0,
        "output_tokens": 0,
    }

    # Step 1: Get contacts missing data
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, email, phone, role, company_name, notes FROM contacts "
            "WHERE (phone = '' OR phone IS NULL) AND (role = '' OR role IS NULL)"
        ).fetchall()
        contacts = [dict(r) for r in rows]

    stats["contacts_targeted"] = len(contacts)
    logger.info("Contacts to enrich: %d", len(contacts))

    if not contacts:
        logger.info("All contacts already enriched!")
        return stats

    # Step 2: Build email index
    target_set = {c["email"].lower() for c in contacts}
    email_index = build_email_index(mail_path, target_set)
    stats["emails_found"] = len(email_index)

    # Only process contacts we have email bodies for
    to_process = [c for c in contacts if c["email"].lower() in email_index]
    logger.info("Will enrich %d contacts (found email bodies)", len(to_process))

    if not to_process:
        logger.warning("No email bodies found for contacts to enrich")
        return stats

    # Step 3: Process in batches
    for i in range(0, len(to_process), batch_size):
        batch_contacts = to_process[i:i + batch_size]
        batch = [
            {"email": c["email"], "body": email_index[c["email"].lower()]}
            for c in batch_contacts
        ]

        logger.info(
            "Batch %d/%d — processing %d contacts...",
            i // batch_size + 1,
            (len(to_process) + batch_size - 1) // batch_size,
            len(batch),
        )

        if dry_run:
            logger.info("  [DRY RUN] Would call Claude API with %d contacts", len(batch))
            continue

        results = extract_batch(batch)
        stats["api_calls"] += 1

        # Step 4: Update contacts
        for item in results:
            email_addr = item.get("email", "").lower()
            # Find matching contact
            matching = next((c for c in batch_contacts if c["email"].lower() == email_addr), None)
            if not matching:
                # Try to match by position if email field is wrong
                idx = results.index(item)
                if idx < len(batch_contacts):
                    matching = batch_contacts[idx]
                    email_addr = matching["email"].lower()

            if not matching:
                continue

            updates = {}

            phone = (item.get("phone") or "").strip()
            if phone and not matching.get("phone"):
                updates["phone"] = phone
                stats["phones_added"] += 1

            role = (item.get("role") or "").strip()
            if role and not matching.get("role"):
                updates["role"] = role[:100]
                stats["roles_added"] += 1

            company = (item.get("company_name") or "").strip()
            if company and (not matching.get("company_name") or
                    matching["company_name"] == matching["email"].split("@")[1].split(".")[0].capitalize()):
                updates["company_name"] = company[:100]
                stats["companies_updated"] += 1

            notes = (item.get("notes") or "").strip()
            if notes and not matching.get("notes"):
                updates["notes"] = notes[:300]
                stats["notes_added"] += 1

            if updates:
                Contact.update(matching["id"], updates)
                logger.info("  ✓ %s → %s", email_addr, list(updates.keys()))
                stats["contacts_enriched"] += 1

        # Rate limiting — be gentle on API
        if i + batch_size < len(to_process):
            time.sleep(0.5)

    return stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    init_db()
    print("Enriching contacts via Claude Sonnet...")
    print()
    result = enrich_with_claude(batch_size=10)
    print()
    print("=== Results ===")
    for k, v in result.items():
        print("  %s: %s" % (k, v))
