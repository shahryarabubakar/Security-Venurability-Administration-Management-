import os


class Config:
    # ── MySQL ──────────────────────────────────────────────────────────────────
    MYSQL_HOST     = os.environ.get('MYSQL_HOST',     'localhost')
    MYSQL_PORT     = int(os.environ.get('MYSQL_PORT', '3306'))
    MYSQL_USER     = os.environ.get('MYSQL_USER',     'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'leo123')
    MYSQL_DB       = os.environ.get('MYSQL_DB',       'svams')

    # ── Flask ──────────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY', 'svams-dev-secret-change-in-production')

    # ── File uploads ───────────────────────────────────────────────────────────
    UPLOAD_FOLDER      = 'uploads'
    ALLOWED_EXTENSIONS = {'json'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024   # 16 MB
