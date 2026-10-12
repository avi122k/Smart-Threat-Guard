
import sqlite3
import os
from datetime import datetime


# --------------------------------
# Database location
# --------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATABASE_PATH = os.path.join(
    BASE_DIR, "data", "scan_history.db"
)

os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)


# --------------------------------
# Database connection
# --------------------------------

def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


# --------------------------------
# Create / migrate database tables
# --------------------------------

def create_table():
    with get_connection() as connection:
        cursor = connection.cursor()

        # User accounts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Existing scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                reasons TEXT,
                features TEXT,
                scan_date TEXT NOT NULL
            )
        """)

        # Check existing columns before migrating
        cursor.execute("PRAGMA table_info(scan_history)")
        columns = {
            column["name"] for column in cursor.fetchall()
        }

        if "features" not in columns:
            cursor.execute("""
                ALTER TABLE scan_history ADD COLUMN features TEXT
            """)

        if "user_id" not in columns:
            cursor.execute("""
                ALTER TABLE scan_history
                ADD COLUMN user_id INTEGER REFERENCES users(id)
            """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_user_id
            ON scan_history(user_id)
        """)


# --------------------------------
# User functions
# --------------------------------

def create_user(username, email, password_hash):
    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO users
                (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            username,
            email.lower(),
            password_hash,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        return cursor.lastrowid


def get_user_by_email(email):
    with get_connection() as connection:
        return connection.execute("""
            SELECT * FROM users WHERE email = ?
        """, (email.lower(),)).fetchone()


def get_user_by_username(username):
    with get_connection() as connection:
        return connection.execute("""
            SELECT * FROM users WHERE username = ?
        """, (username,)).fetchone()


def get_user_by_id(user_id):
    with get_connection() as connection:
        return connection.execute("""
            SELECT id, username, email, created_at
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()


# --------------------------------
# Save scan
# --------------------------------

def save_scan(
    url,
    prediction,
    risk_score,
    risk_level,
    reasons,
    features,
    user_id=None
):
    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO scan_history (
                url, prediction, risk_score, risk_level,
                reasons, features, scan_date, user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            url,
            prediction,
            risk_score,
            risk_level,
            reasons,
            features,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user_id
        ))
        return cursor.lastrowid


# --------------------------------
# Get scans
# --------------------------------

def get_all_scans(user_id=None):
    with get_connection() as connection:
        if user_id is None:
            return connection.execute("""
                SELECT * FROM scan_history ORDER BY id DESC
            """).fetchall()

        return connection.execute("""
            SELECT * FROM scan_history
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,)).fetchall()


def get_scan_by_id(scan_id, user_id=None):
    with get_connection() as connection:
        if user_id is None:
            return connection.execute("""
                SELECT * FROM scan_history WHERE id = ?
            """, (scan_id,)).fetchone()

        return connection.execute("""
            SELECT * FROM scan_history
            WHERE id = ? AND user_id = ?
        """, (scan_id, user_id)).fetchone()


# --------------------------------
# Statistics
# --------------------------------

def get_statistics(user_id=None):
    with get_connection() as connection:
        if user_id is None:
            query = "SELECT * FROM scan_history"
            params = ()
        else:
            query = """
                SELECT * FROM scan_history WHERE user_id = ?
            """
            params = (user_id,)

        rows = connection.execute(query, params).fetchall()

        total = len(rows)
        phishing = sum(
            row["prediction"] == "PHISHING" for row in rows
        )
        legitimate = sum(
            row["prediction"] == "LEGITIMATE" for row in rows
        )
        average_risk = (
            sum(row["risk_score"] for row in rows) / total
            if total else 0
        )

        return {
            "total_scans": total,
            "phishing_scans": phishing,
            "legitimate_scans": legitimate,
            "average_risk": round(average_risk, 2)
        }
