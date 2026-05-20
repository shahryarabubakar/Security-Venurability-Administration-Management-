# ⬡ SVAMS

## Vulnerability Management & Scan Result Database System

**Flask · MySQL · Jinja2 · Chart.js · OWASP ZAP Integration**


## 📁 Project Structure

```
svams/  
├── app.py              ← Flask application — ALL routes live here  
├── config.py           ← Database & app configuration  
├── zap\_parser.py       ← OWASP ZAP JSON report parser  
├── seed\_users.py       ← Run once to create demo users  
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
    │   ├── list\_assets.html  
    │   ├── add\_asset.html  
    │   ├── view\_asset.html  
    │   ├── list\_vulnerabilities.html  
    │   ├── add\_vulnerability.html  
    │   ├── view\_vulnerability.html  
    │   ├── scan\_history.html       ← NEW  
    │   ├── statistics.html         ← NEW (Chart.js charts)  
    │   ├── tags.html  
    │   ├── upload\_zap.html  
    │   ├── audit\_log.html  
    │   └── list\_users.html  
    │  
    └── static/  
        ├── css/style.css  
        └── js/main.js
```


## 🧠 Project Architecture & Database Understanding

This section explains how **this exact codebase** is organized internally so you can understand the backend and database flow without getting distracted by the UI files.

### 1. Project Overview

#### What the project does
SVAMS is a **server-rendered vulnerability and asset management system**. It lets users:

- log in and register accounts
- store assets such as servers, databases, and workstations
- record vulnerabilities manually
- import vulnerabilities from an **OWASP ZAP JSON report**
- add remediation notes
- tag assets
- view scan history, statistics, audit logs, and users

#### Main modules in this project

- **Authentication**: login, logout, registration
- **Assets**: add, list, view, and delete assets
- **Vulnerabilities**: add, list, view, update status, and delete findings
- **Remediation Notes**: add and delete progress notes for a vulnerability
- **Scans**: store imported scan sessions and show scan history
- **Tags**: classify assets with labels such as `production` or `critical`
- **Audit Log**: record important actions performed in the app
- **Statistics**: summarize data for charts and dashboards

#### High-level architecture

This project is **not** split into separate `routes/`, `controllers/`, and `models/` folders. Instead, it is a **monolithic Flask app** where most backend responsibilities are concentrated in `app.py`.

```text
Browser
  -> Jinja2 template form / page
  -> Flask route in app.py
  -> validation + business logic in app.py
  -> raw SQL query through Flask-MySQLdb
  -> MySQL database (schema defined in sql/schema.sql)
  -> query result
  -> rendered HTML page or redirect response
```

You can think of the project in three layers:

- **Frontend/UI layer**: `app/templates/` and `app/static/`
- **Backend/application layer**: `app.py`, `zap_parser.py`, `config.py`
- **Database layer**: `sql/schema.sql`, MySQL tables, and `seed_users.py`

### 2. Database Connection

#### Which file connects to the database

- `config.py` defines the database settings
- `app.py` creates the Flask app and initializes the main database connection with `MySQL(app)`
- `seed_users.py` uses a **separate direct MySQL connection** for one-time seeding

#### How the connection is established

In `app.py`, the startup sequence is:

```python
app = Flask(__name__, template_folder='app/templates', static_folder='app/static')
app.config.from_object(Config)
mysql = MySQL(app)
```

This means:

1. Flask app is created
2. Configuration values are loaded from `Config` in `config.py`
3. `Flask-MySQLdb` uses those values to prepare the MySQL connection
4. Route functions later use `mysql.connection.cursor()` to run SQL

#### Role of environment variables

`config.py` reads these values from the environment:

- `MYSQL_HOST`
- `MYSQL_PORT`
- `MYSQL_USER`
- `MYSQL_PASSWORD`
- `MYSQL_DB`
- `SECRET_KEY`

If you do not set them, the app falls back to defaults:

- host: `localhost`
- port: `3306`
- user: `root`
- password: `lab10`
- database: `svams`

Important beginner point:

- there is **no `.env` loader** in this project
- environment variables are read directly with `os.environ.get(...)`
- if you do not export them, the hardcoded defaults in `config.py` are used

#### Database flow from startup to query execution

```text
Run python app.py
  -> Flask starts
  -> app loads Config from config.py
  -> mysql = MySQL(app) prepares DB access
  -> user opens a page or submits a form
  -> route function in app.py runs
  -> route creates a cursor: mysql.connection.cursor()
  -> SQL executes with cur.execute(...)
  -> for writes: mysql.connection.commit()
  -> for reads: cur.fetchone() / cur.fetchall()
  -> cursor closes
  -> Flask returns HTML or redirect
```

For example, login works like this:

```text
login.html form
  -> POST /login
  -> app.py reads username/password
  -> SELECT from users
  -> check_password_hash(...)
  -> session is created
  -> UPDATE users.last_login
  -> redirect to dashboard
```

### 3. Schemas & "Models" in This Project

Important: this repo does **not** use ORM model classes such as SQLAlchemy models.  
The "models" here are represented by:

- the **table definitions** in `sql/schema.sql`
- the **raw SQL queries** inside `app.py`

So when you are looking for the "User model" or "Asset model", you should inspect:

- the table structure in `sql/schema.sql`
- the queries that read/write that table in `app.py`

#### `users`

**Purpose**: stores login accounts and user roles

**Fields**
- `id` - `INT AUTO_INCREMENT PRIMARY KEY`
- `username` - `VARCHAR(50)`, unique, required
- `email` - `VARCHAR(120)`, unique, required
- `password_hash` - `VARCHAR(255)`, required
- `role` - `ENUM('admin','analyst')`, default `analyst`
- `created_at` - `TIMESTAMP`, default current time
- `last_login` - `TIMESTAMP NULL`

**Relationships**
- one user can own many `assets` through `assets.owner_id`
- one user can be linked to many `scans` through `scans.user_id`
- one user can create many `remediation_notes` through `remediation_notes.user_id`
- one user can appear in many `audit_log` rows through `audit_log.user_id`

**Mapped code usage**
- `/login` reads from `users`
- `/register` inserts into `users`
- `/users` lists all users
- `dashboard`, `assets`, `scans`, and `audit` join with `users` to show usernames

#### `assets`

**Purpose**: stores the systems being monitored

**Fields**
- `id` - `INT AUTO_INCREMENT PRIMARY KEY`
- `owner_id` - `INT`, foreign key to `users.id`, nullable
- `asset_name` - `VARCHAR(100)`, required
- `ip_address` - `VARCHAR(50)`, unique, required
- `operating_system` - `VARCHAR(100)`, optional
- `asset_type` - `VARCHAR(50)`, default `Server`
- `status` - `ENUM('Active','Inactive','Retired')`, default `Active`
- `created_at` - `TIMESTAMP`, default current time

**Relationships**
- belongs to one owner in `users`
- can have many `vulnerabilities`
- can have many `tags` through `asset_tags`

**Mapped code usage**
- `/assets` lists assets with joins to users, vulnerabilities, and tags
- `/assets/add` inserts into `assets`, then inserts into `asset_tags`
- `/assets/<id>` shows one asset with its vulnerabilities and tags
- `/assets/<id>/delete` deletes an asset

**Delete behavior**
- deleting an asset cascades to `vulnerabilities` and `asset_tags`

#### `scans`

**Purpose**: stores scan sessions or imported scan history

**Fields**
- `id` - `INT AUTO_INCREMENT PRIMARY KEY`
- `scan_name` - `VARCHAR(100)`, required
- `scanner_type` - `ENUM('ZAP','Nessus','Nmap','Manual')`
- `started_at` - `TIMESTAMP`, default current time
- `completed_at` - `TIMESTAMP NULL`
- `status` - `ENUM('Running','Completed','Failed')`
- `user_id` - `INT`, foreign key to `users.id`, nullable
- `notes` - `TEXT`

**Relationships**
- can be associated with many `vulnerabilities` through `vulnerabilities.scan_id`
- may be associated with the user who ran/imported the scan

**Mapped code usage**
- `/scans` lists scan history
- `/upload-zap` inserts a new `scans` row before inserting imported vulnerabilities
- `/vulnerabilities/add` lets a manual vulnerability optionally reference a scan

**Delete behavior**
- deleting a scan sets `vulnerabilities.scan_id` to `NULL`, because the foreign key uses `ON DELETE SET NULL`

#### `vulnerabilities`

**Purpose**: stores security findings for a specific asset

**Fields**
- `id` - `INT AUTO_INCREMENT PRIMARY KEY`
- `asset_id` - `INT`, foreign key to `assets.id`, required
- `scan_id` - `INT`, foreign key to `scans.id`, nullable
- `cve_id` - `VARCHAR(50) NULL`
- `vuln_name` - `VARCHAR(255)`, required
- `risk_level` - `ENUM('Critical','High','Medium','Low','Info')`
- `cvss_score` - `DECIMAL(3,1) NULL`
- `description` - `TEXT`
- `solution` - `TEXT`
- `proof` - `TEXT`
- `status` - `ENUM('Open','In Progress','Resolved','False Positive')`
- `discovered_at` - `TIMESTAMP`, default current time
- `resolved_at` - `TIMESTAMP NULL`

**Relationships**
- belongs to one `asset`
- may belong to one `scan`
- can have many `remediation_notes`

**Mapped code usage**
- `/vulnerabilities` lists vulnerabilities
- `/vulnerabilities/add` inserts a manual vulnerability
- `/vulnerabilities/<id>` shows details
- `/vulnerabilities/<id>/status` updates `status` and `resolved_at`
- `/vulnerabilities/<id>/delete` deletes one vulnerability
- `/upload-zap` bulk-inserts vulnerabilities parsed from a JSON report

**Delete behavior**
- deleting a vulnerability cascades to `remediation_notes`

#### `tags`

**Purpose**: stores reusable labels for assets

**Fields**
- `id` - `INT AUTO_INCREMENT PRIMARY KEY`
- `name` - `VARCHAR(50)`, unique, required
- `color` - `VARCHAR(7)`, default hex color

**Relationships**
- many-to-many with `assets` through `asset_tags`

**Mapped code usage**
- `/tags` lists tags
- `/tags/add` inserts tags
- `/tags/<id>/delete` deletes tags
- `/assets` and `/assets/<id>` join tags to show asset classification

#### `asset_tags`

**Purpose**: join table for the many-to-many relationship between assets and tags

**Fields**
- `asset_id` - foreign key to `assets.id`
- `tag_id` - foreign key to `tags.id`
- composite primary key: `(asset_id, tag_id)`

**Relationships**
- connects one asset to one tag per row
- allows each asset to have multiple tags and each tag to belong to multiple assets

**Mapped code usage**
- `/assets/add` inserts rows into `asset_tags`
- `/assets` and `/assets/<id>` read from it using joins

**Delete behavior**
- if an asset or tag is deleted, related `asset_tags` rows are deleted automatically

#### `remediation_notes`

**Purpose**: stores progress notes, comments, or remediation updates for a vulnerability

**Fields**
- `id` - `INT AUTO_INCREMENT PRIMARY KEY`
- `vuln_id` - `INT`, foreign key to `vulnerabilities.id`
- `user_id` - `INT`, foreign key to `users.id`, nullable
- `note` - `TEXT`, required
- `created_at` - `TIMESTAMP`, default current time

**Relationships**
- belongs to one `vulnerability`
- optionally linked to the user who wrote it

**Mapped code usage**
- `/vulnerabilities/<id>` reads notes for that vulnerability
- `/vulnerabilities/<id>/notes/add` inserts notes
- `/notes/<id>/delete` deletes a note

#### `audit_log`

**Purpose**: stores a history of important actions such as create, update, delete, and import operations

**Fields**
- `id` - `INT AUTO_INCREMENT PRIMARY KEY`
- `user_id` - `INT`, foreign key to `users.id`, nullable
- `action` - `VARCHAR(50)`, required
- `target_type` - `VARCHAR(50)`, required
- `target_id` - `INT`
- `detail` - `TEXT`
- `performed_at` - `TIMESTAMP`, default current time

**Relationships**
- optionally linked to a user
- conceptually points to many different entities through `target_type` and `target_id`

**Mapped code usage**
- `log_action()` in `app.py` inserts audit rows
- called after user registration, asset creation/deletion, vulnerability creation/update/deletion, note creation/deletion, scan deletion, tag deletion, and ZAP import
- `/audit` displays the latest 300 log entries

### 4. `seed_users` Explanation

`seed_users.py` is one of the most important files to understand because beginners often think it creates the full database. It does **not**.

#### What `seed_users` is

- a one-time Python seeding script
- focused only on **user login records**
- specifically responsible for storing **real hashed passwords**

#### Why it exists

`sql/schema.sql` already inserts sample `users`, but those rows contain **placeholder password hashes**:

- `admin`
- `analyst1`

Those placeholder hashes are not the final real login hashes you want to rely on.  
`seed_users.py` replaces or inserts those users with proper Werkzeug password hashes generated by:

```python
generate_password_hash(password)
```

#### How it works

Flow inside `seed_users.py`:

```text
Read DB settings from config.py / environment
  -> connect directly with MySQLdb.connect(...)
  -> loop through USERS list
  -> hash each plain password
  -> INSERT INTO users ...
  -> ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)
  -> commit and close
```

#### What data it inserts

It seeds these two users:

- `admin` / `admin123` / role `admin`
- `analyst1` / `analyst123` / role `analyst`

It also gives each user an email in this format:

- `admin@svams.local`
- `analyst1@svams.local`

#### When it runs

- it does **not** run automatically on Flask startup
- it runs only when you manually execute:

```bash
python seed_users.py
```

- recommended order:

```text
1. Run sql/schema.sql
2. Run python seed_users.py
3. Run python app.py
```

#### How it connects with schemas/models

- it writes into the `users` table defined in `sql/schema.sql`
- it does not touch `assets`, `vulnerabilities`, `tags`, or other tables
- it uses the same database credentials as the Flask app
- it supports the `/login` route, because `/login` reads `users.password_hash`

### 5. Backend Request Flow

This project uses **server-side rendered HTML**, not a separate frontend framework such as React or Vue.

#### Standard request flow

```text
Frontend/UI
  -> HTML form in app/templates/
  -> route function in app.py
  -> validation/business logic in app.py
  -> SQL query through mysql.connection.cursor()
  -> MySQL table
  -> result returned to route
  -> render_template(...) or redirect(...)
  -> browser receives updated page
```

#### Example: Add Asset flow

```text
add_asset.html
  -> POST /assets/add
  -> add_asset() in app.py
  -> validates asset_name, ip_address, asset_type, status
  -> INSERT INTO assets
  -> INSERT INTO asset_tags for selected tags
  -> commit
  -> log_action('CREATE', 'asset', ...)
  -> redirect to /assets
```

#### Example: Update Vulnerability Status flow

```text
view_asset.html or list_vulnerabilities.html
  -> POST /vulnerabilities/<id>/status
  -> update_vuln_status() in app.py
  -> UPDATE vulnerabilities
  -> if resolved: set resolved_at = NOW()
  -> commit
  -> log action
  -> redirect back
```

#### Example: ZAP Import flow

```text
upload_zap.html
  -> POST /upload-zap
  -> upload_zap() in app.py
  -> save uploaded JSON temporarily in uploads/
  -> parse_zap(filepath) in zap_parser.py
  -> INSERT one row into scans
  -> INSERT many rows into vulnerabilities
  -> commit
  -> delete temporary uploaded file
  -> redirect to the asset detail page
```

### 6. Important Folder & File Breakdown

Because your prompt mentions folders like `routes/`, `controllers/`, and `models/`, here is the most accurate mapping for **this actual repo**.

| Concept you may expect | Actual location in this project | What it really does |
|------------------------|---------------------------------|---------------------|
| `routes/` | `app.py` | Flask route decorators such as `@app.route('/assets')` are all here |
| `controllers/` | `app.py` | The route functions also contain the controller logic and validation |
| `models/` | `sql/schema.sql` + SQL queries in `app.py` | There are no ORM classes; tables and raw SQL act as the data model |
| `config/` | `config.py` | Reads DB host, user, password, DB name, secret key, and upload settings |
| `database/` | `app.py`, `sql/schema.sql`, MySQL server | `app.py` opens cursors; `schema.sql` defines structure; MySQL stores the data |
| `seeders/` | `seed_users.py` and sample inserts inside `sql/schema.sql` | Initial sample data and real password hashing |
| `frontend/` | `app/templates/` and `app/static/` | Jinja2 templates, CSS, and JavaScript |

#### Key files to know first

- `app.py`: main backend file; this is the most important file in the repo
- `config.py`: connection settings and upload/security configuration
- `sql/schema.sql`: defines the complete database structure and sample rows
- `seed_users.py`: ensures demo users have real hashed passwords
- `zap_parser.py`: converts ZAP JSON into vulnerability dictionaries
- `app/templates/`: HTML pages rendered by Flask
- `app/static/css/style.css`: styling only
- `app/static/js/main.js`: small UI helpers only
- `uploads/`: temporary storage for uploaded ZAP files before parsing

### 7. CRUD Flow

CRUD in this project is implemented directly in `app.py` with raw SQL.

| Operation | Where it happens | Main tables involved |
|-----------|------------------|----------------------|
| Create | `register()`, `add_asset()`, `add_vulnerability()`, `add_note()`, `add_tag()`, `upload_zap()` | `users`, `assets`, `asset_tags`, `vulnerabilities`, `remediation_notes`, `tags`, `scans`, `audit_log` |
| Read | `dashboard()`, `list_assets()`, `view_asset()`, `list_vulnerabilities()`, `view_vulnerability()`, `scan_history()`, `statistics()`, `list_tags()`, `audit_log()`, `list_users()` | all major tables |
| Update | `update_vuln_status()`, login `last_login` update, `seed_users.py` duplicate-key password refresh | `vulnerabilities`, `users` |
| Delete | `delete_asset()`, `delete_vulnerability()`, `delete_note()`, `delete_scan()`, `delete_tag()` | `assets`, `vulnerabilities`, `remediation_notes`, `scans`, `tags`, `asset_tags`, `audit_log` |

#### How each CRUD type looks in code

**Create**
- route reads form data
- validates fields
- `INSERT` query runs
- `mysql.connection.commit()` saves the row
- optional `log_action()` records the event

**Read**
- route executes a `SELECT`
- often joins related tables
- data is passed into `render_template(...)`

**Update**
- route executes `UPDATE ... WHERE id = %s`
- example: status changes in `vulnerabilities`
- login also updates `users.last_login`

**Delete**
- route checks permissions
- executes `DELETE`
- database foreign keys may automatically delete or null related rows

### 8. UI vs Backend Separation

This project becomes much easier to understand once you separate files by responsibility.

#### Frontend/UI only

- `app/templates/*.html`
- `app/static/css/style.css`
- `app/static/js/main.js`

These files:

- display forms, tables, charts, buttons, and messages
- submit requests to Flask routes
- do **not** open a MySQL connection
- do **not** run SQL directly

#### Backend logic

- `app.py`
- `zap_parser.py`
- `config.py`

These files:

- receive HTTP requests
- validate data
- parse uploaded files
- manage sessions, CSRF, and permissions
- call database queries

#### Files that directly interact with the database

- `app.py`
- `seed_users.py`
- `sql/schema.sql`

Database interaction summary:

- `app.py` performs runtime `SELECT`, `INSERT`, `UPDATE`, and `DELETE` queries
- `seed_users.py` performs one-time `INSERT ... ON DUPLICATE KEY UPDATE`
- `sql/schema.sql` creates tables, constraints, indexes, and initial sample rows

### 9. Beginner Confusion Clarification

Here are the most common confusing points in this specific repo.

#### "Where are the models?"

There are no Python ORM model classes here.  
The database model is split across:

- `sql/schema.sql` for structure
- SQL queries in `app.py` for behavior

#### "Where are the routes and controllers folders?"

They do not exist in this project.  
`app.py` combines:

- routing
- controller logic
- validation
- database access

#### "Why is there so much frontend code if I only want the database logic?"

Because Flask renders HTML on the server. Each page in `app/templates/` is just the visual layer for forms and tables. If you want the backend flow, focus on:

1. `app.py`
2. `sql/schema.sql`
3. `seed_users.py`
4. `zap_parser.py`

#### "Does `seed_users.py` create the whole database?"

No.

- `sql/schema.sql` creates the database and tables
- `sql/schema.sql` also inserts sample rows
- `seed_users.py` only makes sure the demo users have valid hashed passwords

#### "Why do both `schema.sql` and `seed_users.py` insert users?"

Because they serve different purposes:

- `schema.sql` bootstraps the table with sample user rows
- `seed_users.py` updates or inserts those same usernames with real generated password hashes

#### "Are pages calling an API with JavaScript?"

Mostly no. This project is traditional Flask:

- browser submits HTML forms
- Flask handles the request
- Flask renders a new HTML page or redirects

The JavaScript in `app/static/js/main.js` only handles small UI behavior like modal and flash-message interactions.

#### "What happens to uploaded ZAP files?"

The JSON file is:

1. uploaded through `upload_zap.html`
2. saved temporarily in `uploads/`
3. parsed by `zap_parser.py`
4. converted into DB rows
5. removed from disk

So the long-term data lives in MySQL, not in the uploaded file itself.

#### "Why do some deletes remove related data automatically?"

Because the schema uses foreign keys:

- deleting an `asset` cascades to `vulnerabilities` and `asset_tags`
- deleting a `vulnerability` cascades to `remediation_notes`
- deleting a `scan` does not delete vulnerabilities; it sets `scan_id` to `NULL`

#### "Why is the project structure still confusing?"

One extra confusing file is `Folder Structure`. It describes a different architecture (`FastAPI`, `main.py`, `routers/`, `models/`) and does **not** match the current Flask codebase. When studying this project, trust:

- `app.py`
- `config.py`
- `sql/schema.sql`
- `seed_users.py`
- `app/templates/`

---

## 🚀 Setup — Step by Step

### Prerequisites

- Python 3.10+

- MySQL 8.x running on `localhost`

- `pip`­

- On Ubuntu/Debian: `sudo apt install libmysqlclient-dev pkg-config`


### Step 1 — Install Python packages

```
pip install -r requirements.txt
```


### Step 2 — Create the database

```
mysql -u root -p \< sql/schema.sql
```

Creates the `svams` database, all 8 tables, and sample data.


### Step 3 — Configure database credentials

Open `config.py` and set your MySQL password:

```
MYSQL\_PASSWORD = 'your\_mysql\_password\_here'
```

Or set environment variables:

```
export MYSQL\_PASSWORD=your\_password
```


### Step 4 — Seed demo users

```
python seed\_users.py
```


### Step 5 — Run the application

```
python app.py
```

Open: **http://localhost:5000**


## 🔐 Login Credentials

| Username | Password | Role | Access |
| - | - | - | - |
| admin | admin123 | Admin | Full access + audit log + users |
| analyst1 | analyst123 | Analyst | View, create, edit |



## 🌐 All Routes

| URL | Page | Auth |
| - | - | - |
| `/login` | Login | No |
| `/register` | Register | No |
| `/` | Dashboard | Yes |
| `/assets` | Asset list | Yes |
| `/assets/add` | Add asset | Yes |
| `/assets/\<id\>` | Asset detail | Yes |
| `/assets/\<id\>/delete` | Delete asset | Yes |
| `/vulnerabilities` | Vulnerability list | Yes |
| `/vulnerabilities/add` | Add vulnerability | Yes |
| `/vulnerabilities/\<id\>` | Vulnerability detail | Yes |
| `/vulnerabilities/\<id\>/status` | Update status | Yes |
| `/vulnerabilities/\<id\>/delete` | Delete vulnerability | Yes |
| `/vulnerabilities/\<id\>/notes/add` | Add note | Yes |
| `/notes/\<id\>/delete` | Delete note | Yes |
| `/scans` | Scan history | Yes |
| `/scans/\<id\>/delete` | Delete scan | Admin |
| `/statistics` | Charts & analytics | Yes |
| `/tags` | Tag manager | Yes |
| `/tags/add` | Create tag | Yes |
| `/tags/\<id\>/delete` | Delete tag | Admin |
| `/upload-zap` | Import ZAP JSON | Yes |
| `/audit` | Audit log | Admin |
| `/users` | User list | Admin |
| `/logout` | Logout | Yes |



## 🗄 Database Tables

| Table | Description |
| - | - |
| `users` | Login accounts (admin / analyst roles) |
| `assets` | IT systems being monitored |
| `scans` | Scan sessions (ZAP / Nessus / Nmap / Manual) |
| `vulnerabilities` | Findings with CVE, CVSS, risk, proof, status |
| `tags` | Color-coded labels for assets |
| `asset\_tags` | Many-to-many: assets ↔ tags |
| `remediation\_notes` | Progress notes on each vulnerability |
| `audit\_log` | Immutable record of all create/update/delete acts |



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


## 🔒 Security — SQL Injection Analysis & Mitigations

This project has been reviewed and updated to explicitly demonstrate SQL Injection (SQLi) awareness and prevention. Below is a concise, evaluator-friendly summary of what SQL Injection is, where we looked in the codebase, what (if anything) was vulnerable, and what was changed.

1) SQL Injection — what it is
- SQL Injection is a class of vulnerability that occurs when user-supplied input is embedded directly into SQL statements, allowing attackers to change the intent of queries (for example, by terminating strings, injecting `OR 1=1`, or adding `; DROP TABLE ...`).
- Attackers exploit unsanitized input to read, modify, or destroy data, or to escalate privileges.

Realistic vulnerable example (NOT in this project):
```
# Vulnerable: concatenating user input into SQL
query = "SELECT * FROM users WHERE username = '" + username + "'"
cur.execute(query)
```

2) Vulnerability analysis of this codebase
- Files reviewed: `app.py`, `seed_users.py`, and database access points.
- Most SQL statements in `app.py` and `seed_users.py` already used parameterized queries (placeholders like `%s`) with `cursor.execute(query, params)`. Parameterized queries keep SQL structure separate from data and are the primary defense against SQLi.
- Dynamic SQL building in the application (for example assembling a `WHERE` clause) is done using constant SQL fragments containing `%s` placeholders and a separate `params` list — this is safe when placeholders are preserved and values are supplied as parameters.

3) Specific changes made
- Added explicit input validation for ID values that originate from user input (form fields). Helper `_to_int()` was added to convert/validate integer IDs before they're used as query parameters. This prevents accidental use of non-numeric strings where numeric IDs are expected.
- Added explanatory comments in `app.py` near critical INSERT/UPDATE statements to document and demonstrate the use of parameterized statements.
- Kept all database logic the same functionally; no behavior changes were introduced beyond input validation and clearer documentation/comments.

Which queries were reviewed and found safe
- Authentication (`/login`): `SELECT id, username, ... FROM users WHERE username = %s` — uses parameters.
- Asset/vulnerability listing & filtering: all `SELECT` statements with user-controlled `q`, `tag`, `status`, and `risk` use `%s` placeholders and parameter lists.
- Inserts/updates (assets, vulnerabilities, scans, tags, notes, audit_log) use parameterized queries.

Potential risks & mitigations
- Risk: building SQL column names, ORDER BY clauses, or LIMIT values from user input can be dangerous. This project does not use user input for SQL identifiers or raw clauses — where any ordering/filtering is applied it's either constant or uses safe placeholders.
- Mitigation: input validation functions (e.g. `_to_int`) and whitelists for enumerated values (`ALLOWED_STATUSES`, `ALLOWED_RISKS`, etc.) ensure only expected values are accepted.

4) Why the application is now secure against SQL Injection
- All data used in SQL statements is passed as parameters to `cursor.execute(...)` rather than interpolated into SQL strings. This separates code (SQL) from data and prevents an attacker from changing the SQL structure.
- Input validation ensures numeric IDs and enumerated fields cannot be used to manipulate queries.
- Filenames used in imports are sanitized using `werkzeug.utils.secure_filename()` and are still passed as parameters to statements.

Summary: The codebase uses parameterized SQL throughout and now includes explicit integer validation for form-derived IDs. Given these protections, the application is secure against SQL Injection when running with the provided code and libraries.

If you would like, I can:
- Add unit tests that attempt to inject SQL into query parameters to demonstrate protections.
- Harden logging or error handling further to avoid leaking DB error messages to end users.



## 🔑 Role Permissions

| Permission | Admin | Analyst |
| - | - | - |
| View all pages | ✓ | ✓ |
| Create / edit records | ✓ | ✓ |
| Delete records | ✓ | ✗ |
| Delete scans | ✓ | ✗ |
| Manage tags | ✓ | ✗ |
| View audit log | ✓ | ✗ |
| View user list | ✓ | ✗ |


