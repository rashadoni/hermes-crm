"""
Outlook Email Sync — Scan corporate mailbox & extract contacts
==============================================================
Connects to Office 365 via IMAP, extracts contacts from email headers,
creates Company and Contact records in CRM database.
"""

import imaplib
import email
import re
import os
import logging
import time
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from typing import List, Dict, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

from models import Contact, Company, Activity, EmailSyncLog
from database import init_db

logger = logging.getLogger(__name__)

IMAP_SERVER = "outlook.office365.com"
IMAP_PORT = 993

# Email domains to skip (internal / generic)
SKIP_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "mail.ru", "yandex.ru", "yandex.com",
    "protonmail.com", "icloud.com", "aol.com",
    "noreply", "no-reply", "mailer-daemon",
}

# Own domain — skip contacts from own company
OWN_DOMAIN = ""
_email_addr = os.getenv("EMAIL_ADDRESS", "")
if "@" in _email_addr:
    OWN_DOMAIN = _email_addr.split("@")[1].lower()


def _decode_str(value):
    # type: (object) -> str
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return value.decode("latin-1", errors="replace")
    return str(value)


def _decode_header_value(raw):
    # type: (Optional[str]) -> str
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


def _get_body(msg):
    # type: (email.message.Message) -> str
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in disposition:
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body = part.get_payload(decode=True).decode(charset, errors="replace")
                    break
                except Exception:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            body = msg.get_payload(decode=True).decode(charset, errors="replace")
        except Exception:
            body = str(msg.get_payload())
    return body.strip()


def _parse_email_addresses(header_value):
    # type: (str) -> List[Tuple[str, str]]
    """Parse comma-separated email addresses from header.
    Returns list of (name, email) tuples.
    """
    if not header_value:
        return []

    results = []
    # Split by comma, handling quoted names
    parts = re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", header_value)
    for part in parts:
        name, addr = parseaddr(part.strip())
        name = _decode_header_value(name) if name else ""
        addr = addr.strip().lower()
        if addr and "@" in addr:
            results.append((name, addr))
    return results


def _domain_from_email(addr):
    # type: (str) -> str
    if "@" in addr:
        return addr.split("@")[1].lower()
    return ""


def _should_skip_email(addr):
    # type: (str) -> bool
    """Check if this email should be skipped."""
    if not addr or "@" not in addr:
        return True
    domain = _domain_from_email(addr)
    local = addr.split("@")[0].lower()

    # Skip own domain
    if OWN_DOMAIN and domain == OWN_DOMAIN:
        return True

    # Skip generic providers
    if domain in SKIP_DOMAINS:
        return True

    # Skip noreply addresses
    if "noreply" in local or "no-reply" in local or "mailer-daemon" in local:
        return True

    return False


def _company_name_from_domain(domain):
    # type: (str) -> str
    """Guess company name from email domain."""
    if not domain:
        return ""
    # Remove common TLDs
    name = domain.split(".")[0]
    # Capitalize
    return name.capitalize()


def _extract_contacts_from_email(msg):
    # type: (email.message.Message) -> List[Dict]
    """Extract all external contacts from a single email."""
    contacts = []
    seen_emails = set()

    for header in ["From", "To", "Cc", "Reply-To"]:
        raw = _decode_header_value(msg.get(header, ""))
        for name, addr in _parse_email_addresses(raw):
            if _should_skip_email(addr):
                continue
            if addr in seen_emails:
                continue
            seen_emails.add(addr)

            domain = _domain_from_email(addr)
            contacts.append({
                "email": addr,
                "name": name,
                "company_name": _company_name_from_domain(domain),
                "domain": domain,
                "source": "EMAIL",
            })

    return contacts


def sync_emails(
    email_address=None,
    password=None,
    folder="INBOX",
    limit=500,
    batch_size=50,
):
    # type: (Optional[str], Optional[str], str, int, int) -> Dict
    """
    Connect to Outlook via IMAP, scan emails, extract and save contacts.

    Returns dict with sync stats.
    """
    email_address = email_address or os.getenv("EMAIL_ADDRESS", "")
    password = password or os.getenv("EMAIL_PASSWORD", "")

    if not email_address or not password:
        return {"error": "EMAIL_ADDRESS and EMAIL_PASSWORD required in .env"}

    if password == "your_app_password_here":
        return {"error": "Please set EMAIL_PASSWORD in .env (use App Password for Office 365)"}

    stats = {
        "emails_scanned": 0,
        "contacts_found": 0,
        "contacts_new": 0,
        "contacts_updated": 0,
        "companies_found": 0,
        "activities_created": 0,
        "errors": 0,
        "skipped_already_synced": 0,
    }

    try:
        logger.info("Connecting to %s as %s...", IMAP_SERVER, email_address)
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(email_address, password)
        logger.info("IMAP login successful")

        # Select folder
        mail.select(folder, readonly=True)

        # Search all emails
        status, message_ids = mail.search(None, "ALL")
        if status != "OK":
            return {"error": "Failed to search mailbox"}

        id_list = message_ids[0].split()
        if not id_list:
            logger.info("No emails found")
            return stats

        # Process most recent first
        id_list = list(reversed(id_list[-limit:]))
        logger.info("Found %d emails to process", len(id_list))

        for i, msg_id in enumerate(id_list):
            try:
                # Fetch headers first to check Message-ID
                status, header_data = mail.fetch(msg_id, "(BODY[HEADER])")
                if status != "OK":
                    stats["errors"] += 1
                    continue

                raw_header = header_data[0][1]
                header_msg = email.message_from_bytes(raw_header)
                message_id = header_msg.get("Message-ID", "").strip()

                # Skip if already synced
                if message_id and EmailSyncLog.is_synced(message_id):
                    stats["skipped_already_synced"] += 1
                    continue

                # Fetch full email
                status, msg_data = mail.fetch(msg_id, "(RFC822)")
                if status != "OK":
                    stats["errors"] += 1
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                subject = _decode_header_value(msg.get("Subject", ""))
                from_addr = _decode_header_value(msg.get("From", ""))
                date_raw = msg.get("Date", "")
                body = _get_body(msg)

                # Parse date
                try:
                    date_str = parsedate_to_datetime(date_raw).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    date_str = date_raw

                # Extract contacts
                contacts = _extract_contacts_from_email(msg)
                stats["emails_scanned"] += 1

                for contact_data in contacts:
                    stats["contacts_found"] += 1
                    domain = contact_data.get("domain", "")

                    # Create or get company
                    company = None
                    if domain:
                        company = Company.create({
                            "name": contact_data.get("company_name", ""),
                            "domain": domain,
                        })
                        if company:
                            contact_data["company_id"] = company["id"]
                            stats["companies_found"] += 1

                    # Check if contact already exists
                    existing = Contact.get_by_email(contact_data["email"])

                    # Create or update contact
                    result = Contact.create(contact_data)
                    if result:
                        if existing:
                            stats["contacts_updated"] += 1
                        else:
                            stats["contacts_new"] += 1

                    # Create activity for this email
                    if result:
                        # Determine direction
                        _, sender_email = parseaddr(from_addr)
                        direction = "INBOUND"
                        if OWN_DOMAIN and _domain_from_email(sender_email.lower()) == OWN_DOMAIN:
                            direction = "OUTBOUND"

                        Activity.create({
                            "contact_id": result["id"],
                            "activity_type": "EMAIL",
                            "direction": direction,
                            "subject": subject[:200],
                            "content": body[:500] if body else "",
                            "metadata": '{"date": "%s"}' % date_str,
                        })
                        stats["activities_created"] += 1

                # Mark as synced
                if message_id:
                    EmailSyncLog.mark_synced(
                        message_id,
                        from_addr=from_addr[:200],
                        subject=subject[:200],
                    )

                # Log progress
                if (i + 1) % batch_size == 0:
                    logger.info(
                        "Progress: %d/%d emails processed (%d contacts found)",
                        i + 1, len(id_list), stats["contacts_found"],
                    )

            except Exception as e:
                logger.warning("Error processing email %s: %s", msg_id, e)
                stats["errors"] += 1
                continue

        mail.logout()
        logger.info(
            "Sync complete: %d emails scanned, %d new contacts, %d updated",
            stats["emails_scanned"],
            stats["contacts_new"],
            stats["contacts_updated"],
        )

    except imaplib.IMAP4.error as e:
        logger.error("IMAP error: %s", e)
        stats["error"] = "IMAP login failed: %s" % str(e)
    except Exception as e:
        logger.error("Sync error: %s", e)
        stats["error"] = str(e)

    return stats


def get_sync_status():
    # type: () -> Dict
    """Get current sync status info."""
    return {
        "total_emails_synced": EmailSyncLog.count(),
        "total_contacts": Contact.count(),
        "total_companies": Company.count(),
        "total_activities": Activity.count(),
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    print("Starting email sync...")
    result = sync_emails(limit=100)
    print("\nSync results:")
    for k, v in result.items():
        print("  %s: %s" % (k, v))
