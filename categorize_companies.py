#!/usr/bin/env python3
"""Categorize companies as client or partner."""
import sqlite3
import os
import re

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crm.db")

# Companies the user listed as CLIENTS — normalized keywords for fuzzy matching
# Each entry: (keywords_to_match_in_name_or_domain, human_readable_name)
CLIENTS = [
    ("aac", "AAC"),
    ("agrarco", "AGRARCO"),
    ("agrofoodinvest", "Agro Food İnvestments"),
    ("atsfood", "ATS FOOD"),
    ("azbadam", "AZBADAM"),
    ("azbiznes", "Azbiznes servis"),
    ("azfish", "Azerbaijan Fish Farm"),
    ("azer-green", "Azerbaijan Green Energy"),
    ("azpoultry", "Azerbaijan Poultry"),
    ("azertexnlayn", "Azertexnolayn"),
    ("azertexnolayn", "Azertexnolayn"),
    ("azersheker", "Azərşəkər"),
    ("azmade", "Azmade Group"),
    ("azrose", "Azrose"),
    ("badamdar", "Badamdar Estates"),
    ("bakugarden", "Baku Garden"),
    ("skygarden", "Baku Garden"),
    ("paulaner", "Paulaner Baku"),
    ("centralpoint", "Central Point Baku"),
    ("cpc", "CPC"),
    ("dastanagro", "Dastan Agro"),
    ("designb", "Design Bureau"),
    ("dost", "Dost Agropark"),
    ("eden", "Eden Agro"),
    ("excelsior", "Excelsior"),
    ("fmg", "Facility Management Group"),
    ("foton", "Foton"),
    ("galaolives", "Gala Olives"),
    ("goygol", "Göygöl Lake Resort"),
    ("grandlogistics", "Grand Logistics Center"),
    ("grandagroinvitro", "Grand-Agro Invitro"),
    ("grandagro", "Grand-Agro"),
    ("greenplant", "Green Plant"),
    ("ibk", "İBK"),
    ("lenkaransprings", "Lenkeran Resort"),
    ("lankaransprings", "Lenkeran Resort"),
    ("lecheq", "Ləcheq Farm and Distillery"),
    ("lkz", "Lənkəran Konserv Zavodu"),
    ("lls", "LLS"),
    ("guven", "Guven Technology"),
    ("marsoverseas", "Mars Overseas"),
    ("mergroup", "Mer Group"),
    ("nohurgol", "Nohurgöl"),
    ("pmdgroup", "PMD Group"),
    ("pmdproject", "PMD Projects"),
    ("pmdhospitality", "PMD Projects"),
    ("qkz", "Qəbələ Konserv Zavodu"),
    ("qubakz", "Quba Konserv Zavodu"),
    ("reveri", "Reveri"),
    ("scandens", "Scandens Pharmaceutical"),
    ("shamkiragropark", "Şəmkir Aqropark"),
    ("sparkbeton", "Spark beton"),
    ("tabia", "Tabia Hospitality"),
    ("aghdamcityhotel", "Yeni Ağdam"),
    ("garabaghotel", "Hilton Ağdam"),
    ("chinarhotel", "Yeni Çinar"),
    ("ramadaplaza", "Ramada Gəncə"),
    ("galaalti", "Yeni Qalaalti"),
    ("zeytunpharma", "Zeytun Pharmaceuticals"),
    ("ztp", "Zəyəm Texnologiyalar Parkı"),
    ("yevlakhcityhotel", "Yeni Naftalan"),
    ("sugovushan", "Yeni Naftalan"),
    ("shamakhihotel", "Shamakhi Hotel"),
    ("shamakhipalace", "Shamakhi Palace"),
]

def normalize(s):
    """Lowercase, remove spaces, dashes, dots for fuzzy comparison."""
    return re.sub(r'[\s\-\._]', '', s.lower())

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Add category column if not exists
    try:
        conn.execute("SELECT category FROM companies LIMIT 1")
    except:
        conn.execute("ALTER TABLE companies ADD COLUMN category TEXT DEFAULT ''")
        conn.commit()
        print("Added 'category' column")

    rows = conn.execute("SELECT id, name, domain FROM companies ORDER BY name").fetchall()
    print(f"Total companies in DB: {len(rows)}")

    client_count = 0
    partner_count = 0
    client_names = []
    partner_names = []

    for row in rows:
        cid = row["id"]
        cname = row["name"]
        cdomain = row["domain"] or ""
        norm_name = normalize(cname)
        norm_domain = normalize(cdomain.split('.')[0] if cdomain else "")

        is_client = False
        matched_to = ""
        for keyword, human_name in CLIENTS:
            kw = normalize(keyword)
            if kw == norm_name or kw in norm_name or norm_name in kw:
                is_client = True
                matched_to = human_name
                break
            if norm_domain and (kw == norm_domain or kw in norm_domain or norm_domain in kw):
                is_client = True
                matched_to = human_name
                break

        if is_client:
            conn.execute("UPDATE companies SET category = 'client' WHERE id = ?", (cid,))
            client_count += 1
            client_names.append(f"  {cname} ({cdomain}) → {matched_to}")
        else:
            conn.execute("UPDATE companies SET category = 'partner' WHERE id = ?", (cid,))
            partner_count += 1
            partner_names.append(f"  {cname} ({cdomain})")

    conn.commit()
    conn.close()

    print(f"\n=== CLIENTS ({client_count}) ===")
    for n in sorted(client_names):
        print(n)

    print(f"\n=== PARTNERS ({partner_count}) ===")
    for n in sorted(partner_names):
        print(n)

    print(f"\nDone! Clients: {client_count}, Partners: {partner_count}")

if __name__ == "__main__":
    main()
