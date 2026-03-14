"""
AI-Powered Contact Enrichment
==============================
Uses Claude to extract role, company, business context from email bodies.
"""

import os
import json
import logging
from typing import Dict, Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = os.getenv("MANAGER_MODEL", "claude-sonnet-4-5-20250929")


def _get_client():
    """Lazy-load Anthropic client."""
    try:
        import anthropic
        return anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    except ImportError:
        logger.error("anthropic package not installed")
        return None
    except Exception as e:
        logger.error("Failed to create Anthropic client: %s", e)
        return None


def enrich_contact_from_email(
    contact_email,
    contact_name,
    email_subject,
    email_body,
    company_domain="",
):
    # type: (str, str, str, str, str) -> Optional[Dict]
    """
    Use Claude to extract enriched contact info from email content.

    Returns dict with keys:
      - role: inferred job title/role
      - company: company name
      - context: business context summary
      - priority: 1-5 (5 = highest)
      - language: detected language (az/ru/en/tr)
      - tags: list of suggested tags
    """
    if not ANTHROPIC_API_KEY:
        logger.warning("No ANTHROPIC_API_KEY — skipping AI enrichment")
        return None

    client = _get_client()
    if not client:
        return None

    # Truncate body to save tokens
    body_preview = email_body[:1500] if email_body else "(empty)"

    prompt = """Analyze this email and extract contact information.

Email from: %s <%s>
Domain: %s
Subject: %s
Body preview:
---
%s
---

Extract and return a JSON object with these fields:
{
  "role": "inferred job title or role (e.g. Sales Manager, CEO, Procurement)",
  "company": "company name (from domain or email content)",
  "context": "1-2 sentence summary of business context / what they want",
  "priority": 3,  // 1=low, 3=normal, 5=critical (decision maker / large deal)
  "language": "az",  // detected language: az, ru, en, tr
  "tags": ["tag1", "tag2"]  // relevant tags like: client, supplier, partner, prospect, government
}

If you cannot determine a field, use empty string or default value.
Return ONLY valid JSON, no markdown or explanation.""" % (
        contact_name, contact_email, company_domain,
        email_subject, body_preview,
    )

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()

        # Clean potential markdown wrapping
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        result = json.loads(text)
        return result

    except json.JSONDecodeError as e:
        logger.warning("Failed to parse AI response as JSON: %s", e)
        return None
    except Exception as e:
        logger.warning("AI enrichment failed: %s", e)
        return None


def enrich_contacts_batch(contacts_with_emails, max_count=20):
    # type: (list, int) -> Dict[str, Dict]
    """
    Enrich multiple contacts. Returns dict of email -> enrichment data.

    contacts_with_emails: list of dicts with keys:
      email, name, subject, body, domain
    """
    results = {}
    count = 0

    for item in contacts_with_emails:
        if count >= max_count:
            break

        email_addr = item.get("email", "")
        if not email_addr:
            continue

        enrichment = enrich_contact_from_email(
            contact_email=email_addr,
            contact_name=item.get("name", ""),
            email_subject=item.get("subject", ""),
            email_body=item.get("body", ""),
            company_domain=item.get("domain", ""),
        )

        if enrichment:
            results[email_addr] = enrichment
            count += 1
            logger.info(
                "Enriched %s: role=%s, company=%s, priority=%s",
                email_addr,
                enrichment.get("role", "?"),
                enrichment.get("company", "?"),
                enrichment.get("priority", "?"),
            )

    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Quick test
    result = enrich_contact_from_email(
        contact_email="test@example.com",
        contact_name="Test User",
        email_subject="Partnership proposal",
        email_body="Dear team, we would like to discuss a potential partnership...",
        company_domain="example.com",
    )
    if result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("Enrichment failed or API key not set")
