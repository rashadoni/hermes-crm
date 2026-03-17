# LeadDrive CRM — Development Rules

## FIRST STEPS (read this EVERY session)
1. **Read this file first** — before any code changes
2. **GitHub is configured**: repo `rashadrahimov/hermes-crm`, branch `main`, token in git remote URL
3. **GitHub Actions auto-deploy**: push to `main` → auto SSH deploy to server (see `.github/workflows/deploy.yml`)
4. **NEVER use admin/exec API, SCP, or manual file copy for deployment** — only `git push origin main`
5. **Sync local repo first**: run `git fetch origin main && git checkout main && git reset --hard origin/main` to get latest server code
6. **Database is PostgreSQL** (NOT SQLite): `postgresql://hermes:hermes@localhost:5432/hermes_crm` via `psycopg2` + `PgConnectionWrapper`
7. **Two auth systems**: CRM admin token (`/api/auth/login`) and Portal token (`/api/portal/auth/login`)
8. **Network from VM is blocked**: cannot SSH/curl to server directly, use GitHub Actions for deploy

## Deployment
- **ALWAYS deploy via GitHub**: commit changes → `git push origin main` → GitHub Actions auto-deploys to server
- **NEVER use SCP, admin/exec API, or manual file copy for deployment**
- Workflow file: `.github/workflows/deploy.yml`
- Server: 178.156.249.177 (Hetzner VDS), path: `/opt/hermes_crm/`
- GitHub repo: `rashadrahimov/hermes-crm` (private), branch: `main`
- GitHub token: stored in git remote URL (search previous session transcripts if lost)
- SSH key for deploy: stored in GitHub Secrets as `SSH_PRIVATE_KEY`

## Tech Stack
- FastAPI backend (`api.py`, ~14000+ lines) + PostgreSQL (`hermes_crm` database)
- Legacy SQLite (`crm.db`) — NOT used for production, only backup
- Vanilla JS SPA (`static/index.html`, ~21000+ lines)
- Gunicorn + Uvicorn workers, service: `hermes-crm`, port: 8766
- Domain: leaddrivecrm.org (legacy: hermescrm.xyz)
- `database.py`: `PgConnectionWrapper` wraps psycopg2, `rewrite_sql()` converts SQLite `?` → PostgreSQL `%s`
- `get_db()` context manager: auto-commits on success, rollbacks on exception

## Code Conventions
- Translations: `t('key')` for translation keys in EN/RU/AZ blocks; `_t(en,ru,az)` for inline
- `currentLang` via `Object.defineProperty`
- `api.get()` returns `{ data, total }`, `api.post()` returns unwrapped `.data`
- `api.remove()` for DELETE (not `api.delete`)
- `send_notification()` MUST be called OUTSIDE `with get_db()` blocks (deadlock prevention)
- Route ordering: specific routes BEFORE parameterized routes (e.g. `/api/xxx/stats` before `/api/xxx/{id}`)
- PostgreSQL: use SAVEPOINTs when queries might fail inside transactions to prevent transaction poisoning

## Git
- Branch: `main` (NOT `master`)
- Token in remote URL for private repo access
- After context compaction: always `git fetch && git checkout main` first
