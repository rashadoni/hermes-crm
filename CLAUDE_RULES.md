# Hermes CRM — Development Rules

## Deployment
- **ALWAYS deploy via GitHub**: commit changes → `git push origin main` → GitHub Actions auto-deploys to server
- **NEVER use SCP, admin/exec API, or manual file copy for deployment**
- Workflow file: `.github/workflows/deploy.yml`
- Server: 178.156.249.177 (Hetzner VDS), path: `/opt/hermes_crm/`
- GitHub repo: `rashadrahimov/hermes-crm` (private)

## Tech Stack
- FastAPI backend (`api.py`) + SQLite (`crm.db`)
- Vanilla JS SPA (`static/index.html`)
- Gunicorn + Uvicorn workers, service: `hermes-crm`
- Domain: hermescrm.xyz

## Code Conventions
- Translations: `t('key')` for translation keys in EN/RU/AZ blocks; `_t(en,ru,az)` for inline
- `currentLang` via `Object.defineProperty`
- `api.get()` returns `{ data, total }`, `api.post()` returns unwrapped `.data`
- `api.remove()` for DELETE (not `api.delete`)
- `send_notification()` MUST be called OUTSIDE `with get_db()` blocks (SQLite deadlock prevention)
- Route ordering: specific routes BEFORE parameterized routes (e.g. `/api/xxx/stats` before `/api/xxx/{id}`)

## Git
- Local repo: `/sessions/youthful-funny-gates/hermes_crm_local/`
- Token in remote URL for private repo access
