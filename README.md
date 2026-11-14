# ACRO E-QUALITY — MVP source package

## Included
- Flask web application with SQLite database
- Password hashing and session login
- Role-based visibility for Admin, Quality Manager, Quality Engineer, Quality Supervisor, Quality Inspector, and Department Engineer
- Workflow: Inspector → Supervisor approval → Quality Engineer approval → Department response → Quality inspection → Closed / Rework
- Audit trail and limited file attachments (PNG/JPG/PDF)
- Initial department summary report

## Important
This is an MVP for review and controlled testing, NOT an approved production deployment.
Do not enter real company production data, employee personal data, or confidential photos until Acro Egypt IT/security approves hosting, backups, access controls, retention, HTTPS, and operational procedures.
The first version still needs company-specific mapping of employees, departments, reporting lines, due dates/SLAs, and KPI definitions.
SQLite is suitable only for a small controlled pilot, not a multi-user production deployment.

## Run locally (Windows / macOS / Linux)
1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Create and activate a virtual environment:
   - Windows: `py -m venv .venv` then `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install packages: `pip install -r requirements.txt`
5. Set a strong admin password (12+ characters) and bootstrap the first admin:
   - Windows PowerShell:
     `$env:ACRO_BOOTSTRAP_ADMIN="1"; $env:ACRO_ADMIN_USER="admin"; $env:ACRO_ADMIN_PASSWORD="Use-A-Strong-Unique-Password"`
   - macOS/Linux:
     `export ACRO_BOOTSTRAP_ADMIN=1; export ACRO_ADMIN_USER=admin; export ACRO_ADMIN_PASSWORD='Use-A-Strong-Unique-Password'`
6. Start: `python app.py`
7. Open `http://127.0.0.1:5000`

The admin account is created only when the bootstrap flag is enabled and no admin exists. Change credentials and set a persistent random `ACRO_SECRET_KEY` before any shared test.

## Pilot setup sequence
1. Admin creates Quality Manager, Quality Engineers, Supervisors, Inspectors, and Department Engineers.
2. Add employee-to-engineer and inspector-to-supervisor mappings according to the approved organization chart.
3. Department Engineer accounts must have exactly the relevant department assigned.
4. Create test memos using fictional data and validate every role's visibility and approval permissions.
5. Ask IT to review authentication, HTTPS/reverse proxy, backup/restore, file scanning, logging, retention, and database migration before deployment.

## Known MVP limitations
- No email/SMS notifications yet.
- No password reset or forced first-login password change.
- No formal SLA calendar, overdue alerts, or export to Excel/PDF yet.
- User-to-engineer/supervisor assignment administration is still basic; the admin interface accepts IDs and needs a safer relationship editor.
- No attachment malware scanning; do not upload untrusted files.
- The quality inspection permission is broad in this MVP and must be tightened to the assigned inspector/quality chain before production.
- No multi-factor authentication, rate limiting, or centralized company SSO.
- The app uses local SQLite and local uploads; do not expose it directly to the public internet.


## Install on phones
This build includes a basic PWA manifest and service worker registration.
After the app is deployed on an HTTPS domain:
- Android: open the site in Chrome, then browser menu → Install app / Add to Home screen.
- iPhone: open the site in Safari → Share → Add to Home Screen.
- Windows: open the site in Edge or Chrome and use the install icon/menu.
Only the static shell is cached; authenticated memo pages and company data are not cached offline.

## Public demo deployment
This source package is not itself a live website. To publish it, an authorized owner must connect a hosting provider or company server, configure environment secrets, persistent storage for SQLite/uploads, HTTPS, and backups. For a public demo, use fictional test data only. Do not place real Acro Egypt information on public hosting without written company/IT approval.
