"""
Extract contracts from lawyer emails using Claude.
Scans emails from Rustam Ramazanov and Saida Safarova,
groups by thread, sends to Claude for contract extraction.
"""

import os, json, re, logging, time, sqlite3, email as emaillib, pathlib
from email.header import decode_header
from email.utils import parseaddr
from dotenv import load_dotenv
load_dotenv()

import anthropic

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crm.db")
MAIL_PATH = os.getenv("APPLE_MAIL_PATH", os.path.expanduser("~/Library/Mail/V10"))
MODEL = os.getenv("CONTRACT_MODEL", "claude-haiku-4-5-20251001")
LAWYERS = {'rustam.ramazanov@gtc.az', 'saida.safarova@gtc.az'}

SYSTEM_PROMPT = """You are a contract data extraction assistant for Guven Technology (GTC), an IT services company.
You will receive email threads from company lawyers. Extract ALL contracts, agreements, and deals mentioned.

Return ONLY a valid JSON array. Each element:
{
  "contract_name": "short descriptive name of the contract/deal",
  "counterparty": "company name (the client, not GTC)",
  "contract_type": "one of: service_agreement, addendum, price_protocol, nda, project, termination, other",
  "amount": "contract amount/value if mentioned, or empty string",
  "currency": "AZN, USD, EUR or empty",
  "start_date": "YYYY-MM-DD if mentioned, or empty",
  "end_date": "YYYY-MM-DD if mentioned, or empty",
  "status": "one of: draft, negotiation, signed, active, expired, terminated, unknown",
  "summary": "1-2 sentence summary in English"
}

Rules:
- Extract EVERY contract, agreement, addendum, protocol mentioned
- GTC/Guven Technology is always the service provider
- The counterparty is always the client company
- If multiple contracts in one thread, return multiple objects
- Dates should be YYYY-MM-DD format
- Return ONLY the JSON array, no explanation
"""


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


def _parse_emlx(fp):
    try:
        with open(fp, "rb") as f:
            first = f.readline()
            try:
                n = int(first.strip())
                raw = f.read(n)
            except:
                f.seek(0)
                raw = f.read()
            return emaillib.message_from_bytes(raw)
    except:
        return None


def _get_text(msg):
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
            except:
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
        except:
            pass
    if plain:
        return plain
    if html:
        html = re.sub(r'<br\s*/?>', '\n', html, flags=re.IGNORECASE)
        html = re.sub(r'<p[^>]*>', '\n', html, flags=re.IGNORECASE)
        html = re.sub(r'<[^>]+>', '', html)
        html = html.replace('&nbsp;', ' ').replace('&amp;', '&')
        return html.strip()
    return ""


def _get_client():
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set")
    return anthropic.Anthropic(api_key=api_key)


def scan_lawyer_emails():
    """Scan Apple Mail for emails from lawyers, group by thread."""
    logger.info("Scanning emails from lawyers...")
    mail_path = pathlib.Path(MAIL_PATH)

    found = []
    count = 0

    for root, dirs, files in os.walk(str(mail_path)):
        dirs[:] = [d for d in dirs if d != "Attachments" and not d.startswith(".")]
        for f in files:
            if not f.endswith('.emlx'):
                continue
            count += 1
            fp = os.path.join(root, f)
            msg = _parse_emlx(fp)
            if not msg:
                continue
            from_raw = _decode_hdr(msg.get("From", ""))
            _, addr = parseaddr(from_raw)
            addr = addr.strip().lower()
            if addr not in LAWYERS:
                continue

            subj = _decode_hdr(msg.get("Subject", ""))
            body = _get_text(msg)
            date = msg.get("Date", "")
            to_raw = _decode_hdr(msg.get("To", ""))

            found.append({
                'from': addr,
                'subject': subj,
                'date': date[:30],
                'to': to_raw[:200],
                'body': body[:3000]
            })

    logger.info("Scanned %d emails, found %d from lawyers", count, len(found))

    # Group by thread
    threads = {}
    for e in found:
        clean_subj = re.sub(r'^(RE:\s*|FW:\s*|Fwd:\s*)+', '', e['subject'], flags=re.IGNORECASE).strip()
        if clean_subj not in threads:
            threads[clean_subj] = []
        threads[clean_subj].append(e)

    logger.info("Grouped into %d threads", len(threads))
    return threads


def extract_contracts_batch(threads_batch):
    """Send batch of threads to Claude for contract extraction."""
    parts = []
    for i, (subj, msgs) in enumerate(threads_batch):
        # Combine thread into one text block
        thread_text = f"Thread: {subj}\n"
        for msg in msgs[:3]:  # Max 3 messages per thread
            body_clean = msg['body'][:1500]
            body_clean = body_clean.encode('utf-8', errors='replace').decode('utf-8')
            thread_text += f"\n--- Email from {msg['from']} ({msg['date']}) ---\n"
            thread_text += f"To: {msg['to'][:100]}\n"
            thread_text += body_clean + "\n"

        parts.append(f"=== Thread {i+1} ===\n{thread_text[:3000]}")

    user_msg = "Extract all contracts from these email threads:\n\n" + "\n\n".join(parts)

    try:
        client = _get_client()
        resp = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = resp.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw.strip())
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        logger.error("Claude error: %s", e)
        return []


def create_contracts_table():
    """Create contracts table in CRM database."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS contracts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contract_name TEXT,
            counterparty TEXT,
            contract_type TEXT DEFAULT 'other',
            amount TEXT DEFAULT '',
            currency TEXT DEFAULT '',
            start_date TEXT DEFAULT '',
            end_date TEXT DEFAULT '',
            status TEXT DEFAULT 'unknown',
            summary TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def run(batch_size=5, clear=False):
    create_contracts_table()

    if clear:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM contracts")
        conn.commit()
        conn.close()
        logger.info("Cleared all existing contracts")

    threads = scan_lawyer_emails()
    thread_list = list(threads.items())

    total_contracts = 0
    total_batches = (len(thread_list) + batch_size - 1) // batch_size
    errors = 0

    conn = sqlite3.connect(DB_PATH)

    for i in range(0, len(thread_list), batch_size):
        batch = thread_list[i:i+batch_size]
        batch_num = i // batch_size + 1
        logger.info("Batch %d/%d — %d threads...", batch_num, total_batches, len(batch))

        results = extract_contracts_batch(batch)

        if not results and batch:
            errors += 1
            if errors >= 3:
                logger.error("Too many consecutive errors, stopping.")
                break

        for contract in results:
            errors = 0  # reset on success
            name = contract.get("contract_name", "").strip()
            if not name:
                continue

            # Check for duplicate
            existing = conn.execute(
                "SELECT id FROM contracts WHERE contract_name = ? AND counterparty = ?",
                (name, contract.get("counterparty", ""))
            ).fetchone()

            if existing:
                continue

            conn.execute("""
                INSERT INTO contracts (contract_name, counterparty, contract_type,
                    amount, currency, start_date, end_date, status, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                name,
                contract.get("counterparty", ""),
                contract.get("contract_type", "other"),
                contract.get("amount", ""),
                contract.get("currency", ""),
                contract.get("start_date", ""),
                contract.get("end_date", ""),
                contract.get("status", "unknown"),
                contract.get("summary", ""),
            ))
            total_contracts += 1
            logger.info("  + %s [%s] — %s", name, contract.get("counterparty", ""), contract.get("status", ""))

        conn.commit()

        if i + batch_size < len(thread_list):
            time.sleep(0.5)

    conn.close()
    logger.info("=== Done! Extracted %d contracts ===", total_contracts)


if __name__ == "__main__":
    import sys
    clear = "--clear" in sys.argv
    print("Extracting contracts from lawyer emails...")
    if clear:
        print("(clearing existing contracts first)")
    print()
    run(batch_size=5, clear=clear)
