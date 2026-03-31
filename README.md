# ⬡ SVAMS
## Vulnerability Management & Scan Result Database System
**Flask · MySQL · Jinja2 · Chart.js · OWASP ZAP Integration**

---

## 📁 Project Structure

```
svams/
├── app.py              ← Flask application — ALL routes live here
├── config.py           ← Database & app configuration
├── zap_parser.py       ← OWASP ZAP JSON report parser
├── seed_users.py       ← Run once to create demo users
├── requirements.txt    ← Python packages
│
├── sql/
│   └── schema.sql      ← Database schema + sample data (run this first)
│
└── app/
    ├── templates/      ← All Jinja2 HTML templates
    │   ├── base.html
    │   ├── login.html
    │   ├── register.html
    │   ├── dashboard.html
    │   ├── list_assets.html
    │   ├── add_asset.html
    │   ├── view_asset.html
    │   ├── list_vulnerabilities.html
    │   ├── add_vulnerability.html
    │   ├── view_vulnerability.html
    │   ├── scan_history.html       ← NEW
    │   ├── statistics.html         ← NEW (Chart.js charts)
    │   ├── tags.html
    │   ├── upload_zap.html
    │   ├── audit_log.html
    │   └── list_users.html
    │
    └── static/
        ├── css/style.css
        └── js/main.js
```

---

## 🚀 Setup — Step by Step

### Prerequisites
- Python 3.10+
- MySQL 8.x running on `localhost`
- `pip`
- On Ubuntu/Debian: `sudo apt install libmysqlclient-dev pkg-config`

---

### Step 1 — Install Python packages
```bash
pip install -r requirements.txt
```

---

### Step 2 — Create the database
```bash
mysql -u root -p < sql/schema.sql
```
Creates the `svams` database, all 8 tables, and sample data.

---

### Step 3 — Configure database credentials
Open `config.py` and set your MySQL password:
```python
MYSQL_PASSWORD = 'your_mysql_password_here'
```
Or set environment variables:
```bash
export MYSQL_PASSWORD=your_password
```

---

### Step 4 — Seed demo users
```bash
python seed_users.py
```

---

### Step 5 — Run the application
```bash
python app.py
```
Open: **http://localhost:5000**

---

## 🔐 Login Credentials

| Username  | Password    | Role    | Access                          |
|-----------|-------------|---------|----------------------------------|
| admin     | admin123    | Admin   | Full access + audit log + users |
| analyst1  | analyst123  | Analyst | View, create, edit               |

---

## 🌐 All Routes

| URL                                    | Page                  | Auth     |
|----------------------------------------|-----------------------|----------|
| `/login`                               | Login                 | No       |
| `/register`                            | Register              | No       |
| `/`                                    | Dashboard             | Yes      |
| `/assets`                              | Asset list            | Yes      |
| `/assets/add`                          | Add asset             | Yes      |
| `/assets/<id>`                         | Asset detail          | Yes      |
| `/assets/<id>/delete`                  | Delete asset          | Yes      |
| `/vulnerabilities`                     | Vulnerability list    | Yes      |
| `/vulnerabilities/add`                 | Add vulnerability     | Yes      |
| `/vulnerabilities/<id>`                | Vulnerability detail  | Yes      |
| `/vulnerabilities/<id>/status`         | Update status         | Yes      |
| `/vulnerabilities/<id>/delete`         | Delete vulnerability  | Yes      |
| `/vulnerabilities/<id>/notes/add`      | Add note              | Yes      |
| `/notes/<id>/delete`                   | Delete note           | Yes      |
| `/scans`                               | Scan history          | Yes      |
| `/scans/<id>/delete`                   | Delete scan           | Admin    |
| `/statistics`                          | Charts & analytics    | Yes      |
| `/tags`                                | Tag manager           | Yes      |
| `/tags/add`                            | Create tag            | Yes      |
| `/tags/<id>/delete`                    | Delete tag            | Admin    |
| `/upload-zap`                          | Import ZAP JSON       | Yes      |
| `/audit`                               | Audit log             | Admin    |
| `/users`                               | User list             | Admin    |
| `/logout`                              | Logout                | Yes      |

---

## 🗄 Database Tables

| Table               | Description                                        |
|---------------------|----------------------------------------------------|
| `users`             | Login accounts (admin / analyst roles)             |
| `assets`            | IT systems being monitored                         |
| `scans`             | Scan sessions (ZAP / Nessus / Nmap / Manual)      |
| `vulnerabilities`   | Findings with CVE, CVSS, risk, proof, status      |
| `tags`              | Color-coded labels for assets                      |
| `asset_tags`        | Many-to-many: assets ↔ tags                       |
| `remediation_notes` | Progress notes on each vulnerability               |
| `audit_log`         | Immutable record of all create/update/delete acts  |

---

## ⚡ Key Features

- **Dashboard** — live stats: critical open, high open, total, resolved
- **Asset Inventory** — search, filter by tag, track owner & status
- **Vulnerability Register** — CVE ID, CVSS score, proof field, risk level, status (Open / In Progress / Resolved / False Positive)
- **Scan History** — every ZAP import or manual scan logged with findings count
- **Statistics** — interactive pie, doughnut, and bar charts (Chart.js)
- **ZAP Import** — upload OWASP ZAP JSON → auto-creates scan record + vulnerabilities
- **Tags** — colour-coded labels on assets
- **Remediation Notes** — threaded notes per vulnerability
- **Audit Log** — admin-only, last 300 actions
- **Role-based access** — admin sees everything; analyst can view/create/edit

---

## 🔑 Role Permissions

| Permission            | Admin | Analyst |
|-----------------------|-------|---------|
| View all pages        | ✓     | ✓       |
| Create / edit records | ✓     | ✓       |
| Delete records        | ✓     | ✗       |
| Delete scans          | ✓     | ✗       |
| Manage tags           | ✓     | ✗       |
| View audit log        | ✓     | ✗       |
| View user list        | ✓     | ✗       |
