import os

class Config:
<<<<<<< HEAD
    # ── MySQL ──────────────────────────────────────────────────────────────────
    MYSQL_HOST     = os.environ.get('MYSQL_HOST',     'localhost')
    MYSQL_PORT     = int(os.environ.get('MYSQL_PORT', '3306'))
    MYSQL_USER     = os.environ.get('MYSQL_USER',     'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '0000')
    MYSQL_DB       = os.environ.get('MYSQL_DB',       'svams')

    # ── Flask ──────────────────────────────────────────────────────────────────
=======
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', '3306'))
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '0000')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'svams')
    
>>>>>>> 323ceae (docs: update README with group details and fix SQL injection documentation)
    SECRET_KEY = os.environ.get('SECRET_KEY', 'svams-dev-secret-change-in-production')
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'json'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
