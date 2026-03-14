"""
Enrich contacts by domain/name when no email body is available.
Claude infers company name from domain, tries to get role from name context.
Run this AFTER enrich_with_claude.py.
"""

import os, json, logging, time, sqlite3
from dotenv import load_dotenv
load_dotenv()

import anthropic

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crm.db")
MODEL = os.getenv("ENRICH_MODEL", "claude-haiku-4-5-20251001")

SYSTEM_PROMPT = """You are a business data assistant. Given a list of contacts (name + email address only),
infer their company name from the email domain and guess their role if possible from context clues.

Return ONLY a valid JSON array. Each element:
{
  "email": "the contact email",
  "company_name": "full proper company name inferred from domain (e.g. azertelecom.az → Azertelecom), empty string if unclear",
  "role": "job title if guessable from name suffix like (CFO), (CEO), (IT) etc, otherwise empty string"
}

Rules:
- Use the email domain to infer the real company name (e.g. pmdgroup.az → PMD Group, gtc.az → GTC, fmg.az → FMG)
- Common .az domains: gtc.az=GTC, pmdgroup.az=PMD Group, fmg.az=FMG, azsf.az=AZSF, bhr.az=BHR, atsfood.az=ATS Food
- For generic domains (gmail.com, yahoo.com, hotmail.com, outlook.com) use empty string for company
- If name has suffix like (CFO) (CEO) (IT) (GTC) extract role from it
- Return ONLY the JSON array, no explanation
"""

def _get_client():
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set in .env")
    return anthropic.Anthropic(api_key=api_key)

def extract_batch(batch):
    lines = []
    for i, item in enumerate(batch):
        lines.append(f"{i+1}. Name: {item['name'] or '(unknown)'}  |  Email: {item['email']}")
    user_msg = "Infer company and role for these contacts:\n\n" + "\n".join(lines)
    try:
        client = _get_client()
        resp = client.messages.create(
            model=MODEL, max_tokens=2048, system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = resp.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception as e:
        logger.error("Claude error: %s", e)
        return []

def run(batch_size=20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT id, email, name, company_name, role FROM contacts
        WHERE (company_name IS NULL OR company_name = '')
        AND email NOT LIKE '%noreply%'
        AND email NOT LIKE '%no-reply%'
        AND email NOT LIKE '%postmaster%'
        ORDER BY email
    """).fetchall()

    contacts = [dict(r) for r in rows]
    logger.info("Contacts to enrich by domain: %d", len(contacts))

    updated = 0
    total_batches = (len(contacts) + batch_size - 1) // batch_size

    for i in range(0, len(contacts), batch_size):
        batch_contacts = contacts[i:i+batch_size]
        batch = [{"email": c["email"], "name": c["name"] or ""} for c in batch_contacts]
        logger.info("Batch %d/%d...", i//batch_size+1, total_batches)

        results = extract_batch(batch)
        for item in results:
            em = (item.get("email") or "").lower().strip()
            match = next((c for c in batch_contacts if c["email"].lower() == em), None)
            if not match:
                idx = results.index(item)
                if idx < len(batch_contacts):
                    match = batch_contacts[idx]
            if not match:
                continue
            updates = {}
            company = (item.get("company_name") or "").strip()
            if company and not match.get("company_name"):
                updates["company_name"] = company[:100]
            role = (item.get("role") or "").strip()
            if role and not match.get("role"):
                updates["role"] = role[:100]
            if updates:
                set_clause = ", ".join(f"{k}=?" for k in updates)
                vals = list(updates.values()) + [match["id"]]
                conn.execute(f"UPDATE contacts SET {set_clause} WHERE id=?", vals)
                logger.info("  ✓ %s → %s", match["email"], list(updates.keys()))
                updated += 1

        conn.commit()
        if i + batch_size < len(contacts):
            time.sleep(0.3)

    conn.close()
    logger.info("Done. Updated: %d", updated)

if __name__ == "__main__":
    print("Enriching contacts by domain/name via Claude...")
    run(batch_size=20)
