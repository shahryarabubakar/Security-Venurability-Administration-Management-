"""
SVAMS — Security Vulnerability & Asset Management System
Vulnerability Management and Scan Result Database System

Flask + MySQL + Jinja2
Run:  python app.py
"""

import os
import re
import secrets
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, abort,
)
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from config import Config
from zap_parser import parse_zap

# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder='app/templates', static_folder='app/static')
app.config.from_object(Config)
mysql = MySQL(app)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_STATUSES  = {'Open', 'In Progress', 'Resolved', 'False Positive'}
ALLOWED_RISKS     = {'Critical', 'High', 'Medium', 'Low', 'Info'}
ALLOWED_ASSET_TYPES = {'Server', 'Workstation', 'Database', 'Network Device', 'Web Application', 'Other'}
ALLOWED_ASSET_STATUSES = {'Active', 'Inactive', 'Retired'}
HEX_COLOR_RE = re.compile(r'^#[0-9A-Fa-f]{6}$')


# ── CSRF ──────────────────────────────────────────────────────────────────────

def _get_csrf_token() -> str:
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


@app.context_processor
def inject_csrf():
    return dict(csrf_token=_get_csrf_token)


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        session_token = session.get('_csrf_token', '')
        form_token    = request.form.get('csrf_token', '')
        if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
            abort(403)


# ── Helpers ───────────────────────────────────────────────────────────────────

def allowed_file(filename: str) -> bool:
    return (
        '.' in filename
        and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    )


def log_action(action: str, target_type: str, target_id, detail: str = ''):
    """Write one row to audit_log. Silently ignores DB errors."""
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO audit_log (user_id, action, target_type, target_id, detail)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (session.get('user_id'), action, target_type, target_id, detail),
        )
        mysql.connection.commit()
        cur.close()
    except Exception:
        pass


# ── Decorators ────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403,
                           title='Forbidden',
                           message='You do not have permission to perform this action.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
                           title='Page Not Found',
                           message='The page you requested could not be found.'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500,
                           title='Server Error',
                           message='An internal error occurred. Please try again later.'), 500


@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum upload size is 16 MB.', 'error')
    return redirect(url_for('upload_zap'))


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        try:
            cur = mysql.connection.cursor()
            cur.execute(
                'SELECT id, username, email, password_hash, role FROM users WHERE username = %s',
                (username,),
            )
            user = cur.fetchone()
            cur.close()
        except Exception:
            flash('A database error occurred. Please try again.', 'error')
            return render_template('login.html')

        if user and check_password_hash(user[3], password):
            # Clear session to prevent session fixation
            session.clear()
            session['user_id']  = user[0]
            session['username'] = user[1]
            session['email']    = user[2]
            session['role']     = user[4]

            try:
                cur2 = mysql.connection.cursor()
                cur2.execute(
                    'UPDATE users SET last_login = NOW() WHERE id = %s', (user[0],)
                )
                mysql.connection.commit()
                cur2.close()
            except Exception:
                pass

            flash(f'Welcome back, {user[1]}!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email',    '').strip()
        password = request.form.get('password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')

        # New accounts are always analyst; admins are promoted via DB/admin tools
        role = 'analyst'

        try:
            cur = mysql.connection.cursor()
            cur.execute(
                'SELECT id FROM users WHERE username = %s OR email = %s',
                (username, email),
            )
            if cur.fetchone():
                flash('Username or email already in use.', 'error')
                cur.close()
                return render_template('register.html')

            hashed = generate_password_hash(password)
            cur.execute(
                'INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)',
                (username, email, hashed, role),
            )
            mysql.connection.commit()
            new_id = cur.lastrowid
            cur.close()
        except Exception:
            flash('A database error occurred. Please try again.', 'error')
            return render_template('register.html')

        log_action('CREATE', 'user', new_id, f'Registered {username}')
        flash('Account created — please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
@login_required
def dashboard():
    try:
        cur = mysql.connection.cursor()

        cur.execute('SELECT COUNT(*) FROM assets')
        total_assets = cur.fetchone()[0]

        cur.execute('SELECT COUNT(*) FROM vulnerabilities')
        total_vulns = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE risk_level='High' AND status='Open'"
        )
        high_open = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE risk_level='Critical' AND status='Open'"
        )
        critical_open = cur.fetchone()[0]

        cur.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE status='Resolved'"
        )
        resolved = cur.fetchone()[0]

        cur.execute(
            """
            SELECT a.id, a.asset_name, a.ip_address, a.status,
                   COALESCE(u.username, 'Unassigned') AS owner,
                   COUNT(v.id) AS vuln_count
            FROM assets a
            LEFT JOIN users u ON a.owner_id = u.id
            LEFT JOIN vulnerabilities v
                   ON a.id = v.asset_id AND v.status != 'Resolved'
            GROUP BY a.id
            ORDER BY a.created_at DESC
            LIMIT 6
            """
        )
        recent_assets = cur.fetchall()

        cur.execute(
            """
            SELECT v.id, v.vuln_name, v.risk_level, v.status,
                   a.asset_name, a.id AS asset_id
            FROM vulnerabilities v
            JOIN assets a ON v.asset_id = a.id
            ORDER BY v.discovered_at DESC
            LIMIT 6
            """
        )
        recent_vulns = cur.fetchall()

        cur.execute(
            """
            SELECT risk_level, COUNT(*) AS cnt
            FROM vulnerabilities
            WHERE status NOT IN ('Resolved', 'False Positive')
            GROUP BY risk_level
            ORDER BY FIELD(risk_level,'Critical','High','Medium','Low','Info')
            """
        )
        risk_data = cur.fetchall()

        cur.execute(
            """
            SELECT a.id, a.asset_name,
                   COUNT(v.id)                           AS total,
                   SUM(v.risk_level = 'High')            AS highs,
                   SUM(v.risk_level = 'Critical')        AS criticals
            FROM assets a
            JOIN vulnerabilities v ON a.id = v.asset_id
            WHERE v.status NOT IN ('Resolved', 'False Positive')
            GROUP BY a.id
            ORDER BY criticals DESC, highs DESC, total DESC
            LIMIT 5
            """
        )
        top_assets = cur.fetchall()
        cur.close()

    except Exception:
        flash('Error loading dashboard data.', 'error')
        return render_template('dashboard.html', stats={}, recent_assets=[],
                               recent_vulns=[], risk_data=[], top_assets=[])

    stats = dict(
        total_assets=total_assets,
        total_vulns=total_vulns,
        high_open=high_open,
        critical_open=critical_open,
        resolved=resolved,
    )
    return render_template(
        'dashboard.html',
        stats=stats,
        recent_assets=recent_assets,
        recent_vulns=recent_vulns,
        risk_data=risk_data,
        top_assets=top_assets,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ASSETS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/assets')
@login_required
def list_assets():
    search     = request.args.get('q',   '').strip()
    tag_filter = request.args.get('tag', '')

    cur = mysql.connection.cursor()

    query = """
        SELECT a.id, a.asset_name, a.ip_address, a.operating_system,
               a.asset_type, a.status,
               COALESCE(u.username, 'Unassigned') AS owner,
               COUNT(DISTINCT v.id)               AS vuln_count,
               GROUP_CONCAT(DISTINCT t.name  ORDER BY t.name SEPARATOR ',') AS tags,
               GROUP_CONCAT(DISTINCT t.color ORDER BY t.name SEPARATOR ',') AS tag_colors
        FROM assets a
        LEFT JOIN users u ON a.owner_id = u.id
        LEFT JOIN vulnerabilities v
               ON a.id = v.asset_id AND v.status NOT IN ('Resolved','False Positive')
        LEFT JOIN asset_tags at2 ON a.id  = at2.asset_id
        LEFT JOIN tags t         ON at2.tag_id = t.id
    """
    params, where = [], []

    if search:
        where.append(
            '(a.asset_name LIKE %s OR a.ip_address LIKE %s OR a.operating_system LIKE %s)'
        )
        params += [f'%{search}%', f'%{search}%', f'%{search}%']

    if tag_filter:
        where.append('t.name = %s')
        params.append(tag_filter)

    if where:
        query += ' WHERE ' + ' AND '.join(where)

    query += ' GROUP BY a.id ORDER BY a.created_at DESC'
    cur.execute(query, params)
    assets = cur.fetchall()

    cur.execute('SELECT id, name, color FROM tags ORDER BY name')
    all_tags = cur.fetchall()
    cur.close()

    return render_template(
        'list_assets.html',
        assets=assets,
        all_tags=all_tags,
        search=search,
        tag_filter=tag_filter,
    )


@app.route('/assets/add', methods=['GET', 'POST'])
@login_required
def add_asset():
    cur = mysql.connection.cursor()
    cur.execute('SELECT id, username FROM users ORDER BY username')
    users = cur.fetchall()
    cur.execute('SELECT id, name, color FROM tags ORDER BY name')
    all_tags = cur.fetchall()

    if request.method == 'POST':
        asset_name = request.form.get('asset_name', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        os_name    = request.form.get('operating_system', '').strip()
        asset_type = request.form.get('asset_type', 'Server')
        status     = request.form.get('status',     'Active')
        owner_id   = request.form.get('owner_id')  or None
        tag_ids    = request.form.getlist('tag_ids')

        if not asset_name or not ip_address:
            flash('Asset name and IP address are required.', 'error')
            cur.close()
            return render_template('add_asset.html', users=users, all_tags=all_tags)

        if asset_type not in ALLOWED_ASSET_TYPES:
            asset_type = 'Server'
        if status not in ALLOWED_ASSET_STATUSES:
            status = 'Active'

        try:
            cur.execute(
                """
                INSERT INTO assets
                    (owner_id, asset_name, ip_address, operating_system, asset_type, status)
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (owner_id, asset_name, ip_address, os_name, asset_type, status),
            )
            mysql.connection.commit()
            asset_id = cur.lastrowid

            for tid in tag_ids:
                if str(tid).isdigit():
                    cur.execute(
                        'INSERT IGNORE INTO asset_tags (asset_id, tag_id) VALUES (%s,%s)',
                        (asset_id, int(tid)),
                    )
            mysql.connection.commit()
            cur.close()
        except Exception:
            flash('Error saving asset. The IP address may already be in use.', 'error')
            try:
                cur.close()
            except Exception:
                pass
            cur2 = mysql.connection.cursor()
            cur2.execute('SELECT id, username FROM users ORDER BY username')
            users = cur2.fetchall()
            cur2.execute('SELECT id, name, color FROM tags ORDER BY name')
            all_tags = cur2.fetchall()
            cur2.close()
            return render_template('add_asset.html', users=users, all_tags=all_tags)

        log_action('CREATE', 'asset', asset_id, f'Added {asset_name}')
        flash(f'Asset "{asset_name}" added.', 'success')
        return redirect(url_for('list_assets'))

    cur.close()
    return render_template('add_asset.html', users=users, all_tags=all_tags)


@app.route('/assets/<int:asset_id>')
@login_required
def view_asset(asset_id):
    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT a.id, a.asset_name, a.ip_address, a.operating_system,
               a.asset_type, a.status, a.created_at,
               COALESCE(u.username, 'Unassigned') AS owner
        FROM assets a
        LEFT JOIN users u ON a.owner_id = u.id
        WHERE a.id = %s
        """,
        (asset_id,),
    )
    asset = cur.fetchone()
    if not asset:
        flash('Asset not found.', 'error')
        cur.close()
        return redirect(url_for('list_assets'))

    cur.execute(
        """
        SELECT v.id, v.vuln_name, v.risk_level, v.description,
               v.solution, v.status, v.discovered_at,
               COUNT(rn.id) AS note_count,
               v.cve_id, v.cvss_score
        FROM vulnerabilities v
        LEFT JOIN remediation_notes rn ON v.id = rn.vuln_id
        WHERE v.asset_id = %s
        GROUP BY v.id
        ORDER BY FIELD(v.risk_level,'Critical','High','Medium','Low','Info'),
                 v.discovered_at DESC
        """,
        (asset_id,),
    )
    vulns = cur.fetchall()

    cur.execute(
        """
        SELECT t.id, t.name, t.color
        FROM tags t
        JOIN asset_tags at2 ON t.id = at2.tag_id
        WHERE at2.asset_id = %s
        """,
        (asset_id,),
    )
    asset_tags = cur.fetchall()
    cur.close()

    return render_template(
        'view_asset.html',
        asset=asset,
        vulns=vulns,
        asset_tags=asset_tags,
    )


@app.route('/assets/<int:asset_id>/delete', methods=['POST'])
@login_required
def delete_asset(asset_id):
    cur = mysql.connection.cursor()
    cur.execute('SELECT asset_name, owner_id FROM assets WHERE id = %s', (asset_id,))
    row = cur.fetchone()

    if not row:
        flash('Asset not found.', 'error')
        cur.close()
        return redirect(url_for('list_assets'))

    if session.get('role') != 'admin' and row[1] != session.get('user_id'):
        flash('You do not have permission to delete this asset.', 'error')
        cur.close()
        return redirect(url_for('view_asset', asset_id=asset_id))

    cur.execute('DELETE FROM assets WHERE id = %s', (asset_id,))
    mysql.connection.commit()
    log_action('DELETE', 'asset', asset_id, f'Deleted {row[0]}')
    flash(f'Asset "{row[0]}" deleted.', 'success')
    cur.close()
    return redirect(url_for('list_assets'))


# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/vulnerabilities')
@login_required
def list_vulnerabilities():
    risk_filter   = request.args.get('risk',   '')
    status_filter = request.args.get('status', '')
    search        = request.args.get('q',      '').strip()

    if risk_filter not in ALLOWED_RISKS | {''}:
        risk_filter = ''
    if status_filter not in ALLOWED_STATUSES | {''}:
        status_filter = ''

    cur = mysql.connection.cursor()

    query = """
        SELECT v.id, v.vuln_name, v.risk_level, v.status, v.discovered_at,
               a.asset_name, a.id AS asset_id,
               COUNT(rn.id) AS note_count,
               v.cve_id, v.cvss_score
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        LEFT JOIN remediation_notes rn ON v.id = rn.vuln_id
    """
    params, where = [], []

    if risk_filter:
        where.append('v.risk_level = %s')
        params.append(risk_filter)
    if status_filter:
        where.append('v.status = %s')
        params.append(status_filter)
    if search:
        where.append('(v.vuln_name LIKE %s OR a.asset_name LIKE %s OR v.cve_id LIKE %s)')
        params += [f'%{search}%', f'%{search}%', f'%{search}%']

    if where:
        query += ' WHERE ' + ' AND '.join(where)

    query += """
        GROUP BY v.id
        ORDER BY FIELD(v.risk_level,'Critical','High','Medium','Low','Info'),
                 v.discovered_at DESC
    """
    cur.execute(query, params)
    vulns = cur.fetchall()
    cur.close()

    return render_template(
        'list_vulnerabilities.html',
        vulns=vulns,
        risk_filter=risk_filter,
        status_filter=status_filter,
        search=search,
    )


@app.route('/vulnerabilities/add', methods=['GET', 'POST'])
@login_required
def add_vulnerability():
    cur = mysql.connection.cursor()
    cur.execute('SELECT id, asset_name FROM assets ORDER BY asset_name')
    assets = cur.fetchall()
    cur.execute('SELECT id, scan_name FROM scans ORDER BY started_at DESC')
    scans = cur.fetchall()

    if request.method == 'POST':
        asset_id    = request.form.get('asset_id')
        vuln_name   = request.form.get('vuln_name',   '').strip()
        risk_level  = request.form.get('risk_level',  'Low')
        cve_id      = request.form.get('cve_id',      '').strip() or None
        cvss_score  = request.form.get('cvss_score',  '').strip() or None
        description = request.form.get('description', '').strip()
        solution    = request.form.get('solution',    '').strip()
        proof       = request.form.get('proof',       '').strip()
        status      = request.form.get('status',      'Open')
        scan_id     = request.form.get('scan_id')     or None

        if not asset_id or not vuln_name:
            flash('Asset and vulnerability name are required.', 'error')
            cur.close()
            return render_template('add_vulnerability.html', assets=assets, scans=scans)

        if risk_level not in ALLOWED_RISKS:
            risk_level = 'Low'
        if status not in ALLOWED_STATUSES:
            status = 'Open'

        if cvss_score is not None:
            try:
                cvss_val = float(cvss_score)
                if not (0.0 <= cvss_val <= 10.0):
                    cvss_score = None
            except ValueError:
                cvss_score = None

        try:
            cur.execute(
                """
                INSERT INTO vulnerabilities
                    (asset_id, scan_id, cve_id, vuln_name, risk_level, cvss_score,
                     description, solution, proof, status)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (asset_id, scan_id, cve_id, vuln_name, risk_level, cvss_score,
                 description, solution, proof, status),
            )
            mysql.connection.commit()
            vuln_id = cur.lastrowid
            cur.close()
        except Exception:
            flash('Error saving vulnerability. Please try again.', 'error')
            cur.close()
            return render_template('add_vulnerability.html', assets=assets, scans=scans)

        log_action('CREATE', 'vulnerability', vuln_id,
                   f'Added {vuln_name} on asset {asset_id}')
        flash(f'Vulnerability "{vuln_name}" added.', 'success')
        return redirect(url_for('list_vulnerabilities'))

    cur.close()
    return render_template('add_vulnerability.html', assets=assets, scans=scans)


@app.route('/vulnerabilities/<int:vuln_id>')
@login_required
def view_vulnerability(vuln_id):
    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT v.id, v.vuln_name, v.risk_level, v.description,
               v.solution, v.status, v.discovered_at,
               a.asset_name, a.id AS asset_id,
               v.cve_id, v.cvss_score, v.proof
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE v.id = %s
        """,
        (vuln_id,),
    )
    vuln = cur.fetchone()
    if not vuln:
        flash('Vulnerability not found.', 'error')
        cur.close()
        return redirect(url_for('list_vulnerabilities'))

    cur.execute(
        """
        SELECT rn.id, rn.note, rn.created_at,
               COALESCE(u.username, 'System') AS author,
               rn.user_id
        FROM remediation_notes rn
        LEFT JOIN users u ON rn.user_id = u.id
        WHERE rn.vuln_id = %s
        ORDER BY rn.created_at ASC
        """,
        (vuln_id,),
    )
    notes = cur.fetchall()
    cur.close()

    return render_template('view_vulnerability.html', vuln=vuln, notes=notes)


@app.route('/vulnerabilities/<int:vuln_id>/status', methods=['POST'])
@login_required
def update_vuln_status(vuln_id):
    new_status = request.form.get('status', 'Open')
    if new_status not in ALLOWED_STATUSES:
        flash('Invalid status value.', 'error')
        return redirect(request.referrer or url_for('list_vulnerabilities'))

    cur = mysql.connection.cursor()
    if new_status == 'Resolved':
        cur.execute(
            'UPDATE vulnerabilities SET status=%s, resolved_at=NOW() WHERE id=%s',
            (new_status, vuln_id),
        )
    else:
        cur.execute(
            'UPDATE vulnerabilities SET status=%s, resolved_at=NULL WHERE id=%s',
            (new_status, vuln_id),
        )
    mysql.connection.commit()
    cur.close()
    log_action('UPDATE', 'vulnerability', vuln_id, f'Status → {new_status}')
    flash('Status updated.', 'success')
    return redirect(request.referrer or url_for('list_vulnerabilities'))


@app.route('/vulnerabilities/<int:vuln_id>/delete', methods=['POST'])
@login_required
def delete_vulnerability(vuln_id):
    if session.get('role') != 'admin':
        flash('Admin access required to delete vulnerabilities.', 'error')
        return redirect(url_for('view_vulnerability', vuln_id=vuln_id))

    cur = mysql.connection.cursor()
    cur.execute('SELECT asset_id FROM vulnerabilities WHERE id = %s', (vuln_id,))
    row = cur.fetchone()
    if not row:
        flash('Vulnerability not found.', 'error')
        cur.close()
        return redirect(url_for('list_vulnerabilities'))

    asset_id = row[0]
    cur.execute('DELETE FROM vulnerabilities WHERE id = %s', (vuln_id,))
    mysql.connection.commit()
    cur.close()
    log_action('DELETE', 'vulnerability', vuln_id, '')
    flash('Vulnerability deleted.', 'success')
    return redirect(url_for('view_asset', asset_id=asset_id))


# ═══════════════════════════════════════════════════════════════════════════════
# REMEDIATION NOTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/vulnerabilities/<int:vuln_id>/notes/add', methods=['POST'])
@login_required
def add_note(vuln_id):
    note_text = request.form.get('note', '').strip()
    if not note_text:
        flash('Note cannot be empty.', 'error')
        return redirect(url_for('view_vulnerability', vuln_id=vuln_id))

    cur = mysql.connection.cursor()
    cur.execute('SELECT id FROM vulnerabilities WHERE id = %s', (vuln_id,))
    if not cur.fetchone():
        flash('Vulnerability not found.', 'error')
        cur.close()
        return redirect(url_for('list_vulnerabilities'))

    cur.execute(
        'INSERT INTO remediation_notes (vuln_id, user_id, note) VALUES (%s,%s,%s)',
        (vuln_id, session['user_id'], note_text),
    )
    mysql.connection.commit()
    note_id = cur.lastrowid
    cur.close()
    log_action('CREATE', 'note', note_id, f'Note on vuln #{vuln_id}')
    flash('Note added.', 'success')
    return redirect(url_for('view_vulnerability', vuln_id=vuln_id))


@app.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    cur = mysql.connection.cursor()
    cur.execute('SELECT vuln_id, user_id FROM remediation_notes WHERE id = %s', (note_id,))
    row = cur.fetchone()

    if not row:
        flash('Note not found.', 'error')
        cur.close()
        return redirect(url_for('list_vulnerabilities'))

    vuln_id, note_user_id = row
    if session.get('role') != 'admin' and note_user_id != session.get('user_id'):
        flash('You can only delete your own notes.', 'error')
        cur.close()
        return redirect(url_for('view_vulnerability', vuln_id=vuln_id))

    cur.execute('DELETE FROM remediation_notes WHERE id = %s', (note_id,))
    mysql.connection.commit()
    log_action('DELETE', 'note', note_id, f'Deleted note on vuln #{vuln_id}')
    cur.close()
    flash('Note deleted.', 'success')
    return redirect(url_for('view_vulnerability', vuln_id=vuln_id))


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/scans')
@login_required
def scan_history():
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT s.id, s.scan_name, s.scanner_type, s.started_at,
               s.completed_at, s.status, s.notes,
               COALESCE(u.username, 'System') AS run_by,
               COUNT(v.id) AS vuln_count
        FROM scans s
        LEFT JOIN users u ON s.user_id = u.id
        LEFT JOIN vulnerabilities v ON v.scan_id = s.id
        GROUP BY s.id
        ORDER BY s.started_at DESC
        """
    )
    scans = cur.fetchall()
    cur.close()
    return render_template('scan_history.html', scans=scans)


@app.route('/scans/<int:scan_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_scan(scan_id):
    cur = mysql.connection.cursor()
    cur.execute('SELECT scan_name FROM scans WHERE id = %s', (scan_id,))
    row = cur.fetchone()
    if not row:
        flash('Scan not found.', 'error')
        cur.close()
        return redirect(url_for('scan_history'))
    cur.execute('DELETE FROM scans WHERE id = %s', (scan_id,))
    mysql.connection.commit()
    log_action('DELETE', 'scan', scan_id, f'Deleted scan: {row[0]}')
    cur.close()
    flash('Scan record deleted.', 'success')
    return redirect(url_for('scan_history'))


# ═══════════════════════════════════════════════════════════════════════════════
# STATISTICS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/statistics')
@login_required
def statistics():
    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT risk_level, COUNT(*) AS cnt
        FROM vulnerabilities
        WHERE status NOT IN ('Resolved','False Positive')
        GROUP BY risk_level
        ORDER BY FIELD(risk_level,'Critical','High','Medium','Low','Info')
        """
    )
    risk_counts = cur.fetchall()

    cur.execute(
        """
        SELECT status, COUNT(*) AS cnt
        FROM vulnerabilities
        GROUP BY status
        ORDER BY FIELD(status,'Open','In Progress','Resolved','False Positive')
        """
    )
    status_counts = cur.fetchall()

    cur.execute(
        """
        SELECT scanner_type, COUNT(*) AS cnt
        FROM scans
        GROUP BY scanner_type
        """
    )
    scanner_counts = cur.fetchall()

    cur.execute(
        """
        SELECT a.asset_name, COUNT(v.id) AS cnt
        FROM assets a
        JOIN vulnerabilities v ON a.id = v.asset_id
        WHERE v.status NOT IN ('Resolved','False Positive')
        GROUP BY a.id
        ORDER BY cnt DESC
        LIMIT 5
        """
    )
    top_assets = cur.fetchall()

    cur.close()

    return render_template(
        'statistics.html',
        risk_counts=risk_counts,
        status_counts=status_counts,
        scanner_counts=scanner_counts,
        top_assets=top_assets,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TAGS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/tags')
@login_required
def list_tags():
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT t.id, t.name, t.color, COUNT(at2.asset_id) AS asset_count
        FROM tags t
        LEFT JOIN asset_tags at2 ON t.id = at2.tag_id
        GROUP BY t.id
        ORDER BY t.name
        """
    )
    tags = cur.fetchall()
    cur.close()
    return render_template('tags.html', tags=tags)


@app.route('/tags/add', methods=['POST'])
@login_required
def add_tag():
    name  = request.form.get('name',  '').strip()
    color = request.form.get('color', '#4f8ef7')

    if not name:
        flash('Tag name is required.', 'error')
        return redirect(url_for('list_tags'))

    if len(name) > 50:
        flash('Tag name must be 50 characters or fewer.', 'error')
        return redirect(url_for('list_tags'))

    if not HEX_COLOR_RE.match(color):
        color = '#4f8ef7'

    cur = mysql.connection.cursor()
    cur.execute(
        'INSERT IGNORE INTO tags (name, color) VALUES (%s,%s)',
        (name, color),
    )
    mysql.connection.commit()
    cur.close()
    flash(f'Tag "{name}" created.', 'success')
    return redirect(url_for('list_tags'))


@app.route('/tags/<int:tag_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_tag(tag_id):
    cur = mysql.connection.cursor()
    cur.execute('SELECT name FROM tags WHERE id = %s', (tag_id,))
    row = cur.fetchone()
    if not row:
        flash('Tag not found.', 'error')
        cur.close()
        return redirect(url_for('list_tags'))
    cur.execute('DELETE FROM tags WHERE id = %s', (tag_id,))
    mysql.connection.commit()
    log_action('DELETE', 'tag', tag_id, f'Deleted tag: {row[0]}')
    cur.close()
    flash('Tag deleted.', 'success')
    return redirect(url_for('list_tags'))


# ═══════════════════════════════════════════════════════════════════════════════
# ZAP UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/upload-zap', methods=['GET', 'POST'])
@login_required
def upload_zap():
    cur = mysql.connection.cursor()
    cur.execute('SELECT id, asset_name FROM assets ORDER BY asset_name')
    assets = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        asset_id = request.form.get('asset_id')
        file     = request.files.get('zap_file')

        if not asset_id:
            flash('Please select an asset.', 'error')
            return render_template('upload_zap.html', assets=assets)

        if not file or not file.filename:
            flash('Please select a file to upload.', 'error')
            return render_template('upload_zap.html', assets=assets)

        if not allowed_file(file.filename):
            flash('Only .json files are accepted.', 'error')
            return render_template('upload_zap.html', assets=assets)

        filename = secure_filename(file.filename)
        if not filename:
            flash('Invalid filename.', 'error')
            return render_template('upload_zap.html', assets=assets)

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            vulns = parse_zap(filepath)
        except (ValueError, FileNotFoundError) as e:
            flash(f'ZAP parse error: {e}', 'error')
            try:
                os.remove(filepath)
            except OSError:
                pass
            return render_template('upload_zap.html', assets=assets)

        try:
            os.remove(filepath)
        except OSError:
            pass

        try:
            cur = mysql.connection.cursor()
            cur.execute(
                """
                INSERT INTO scans (scan_name, scanner_type, status, user_id, notes)
                VALUES (%s, 'ZAP', 'Completed', %s, %s)
                """,
                (
                    f'ZAP Import — {filename}',
                    session.get('user_id'),
                    f'Imported {len(vulns)} findings from {filename}',
                ),
            )
            mysql.connection.commit()
            scan_id = cur.lastrowid

            for v in vulns:
                cur.execute(
                    """
                    INSERT INTO vulnerabilities
                        (asset_id, scan_id, vuln_name, risk_level,
                         description, solution, status)
                    VALUES (%s,%s,%s,%s,%s,%s,'Open')
                    """,
                    (asset_id, scan_id,
                     v['vuln_name'], v['risk_level'],
                     v['description'], v['solution']),
                )
            mysql.connection.commit()
            cur.close()
        except Exception:
            flash('Database error while saving vulnerabilities. Please try again.', 'error')
            return render_template('upload_zap.html', assets=assets)

        log_action('IMPORT', 'vulnerability', int(asset_id),
                   f'ZAP import: {len(vulns)} vulns from {filename}')
        flash(f'Imported {len(vulns)} vulnerabilities from ZAP report.', 'success')
        return redirect(url_for('view_asset', asset_id=asset_id))

    return render_template('upload_zap.html', assets=assets)


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG  (admin only)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/audit')
@login_required
@admin_required
def audit_log():
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT al.id, COALESCE(u.username,'System') AS actor,
               al.action, al.target_type, al.target_id,
               al.detail, al.performed_at
        FROM audit_log al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.performed_at DESC
        LIMIT 300
        """
    )
    logs = cur.fetchall()
    cur.close()
    return render_template('audit_log.html', logs=logs)


# ═══════════════════════════════════════════════════════════════════════════════
# USERS  (admin only)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/users')
@login_required
@admin_required
def list_users():
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT u.id, u.username, u.email, u.role, u.created_at,
               COUNT(DISTINCT a.id) AS asset_count,
               u.last_login
        FROM users u
        LEFT JOIN assets a ON u.id = a.owner_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
        """
    )
    users = cur.fetchall()
    cur.close()
    return render_template('list_users.html', users=users)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, port=5000)
