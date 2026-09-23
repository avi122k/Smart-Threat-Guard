import sqlite3
import os
from datetime import datetime


# --------------------------------
# Database location
# --------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "data",
    "scan_history.db"
)


# --------------------------------
# Database connection
# --------------------------------

def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# --------------------------------
# Create / update database table
# --------------------------------

def create_table():

    connection = get_connection()

    cursor = connection.cursor()


    # Create table if it doesn't exist
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


    # --------------------------------
    # Check existing columns
    # --------------------------------

    cursor.execute("""
        PRAGMA table_info(scan_history)
    """)

    columns = [
        column["name"]
        for column in cursor.fetchall()
    ]


    # --------------------------------
    # Add features column if missing
    # --------------------------------

    if "features" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN features TEXT
        """)


    connection.commit()

    connection.close()


# --------------------------------
# Save scan
# --------------------------------

def save_scan(
    url,
    prediction,
    risk_score,
    risk_level,
    reasons,
    features
):

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO scan_history
        (
            url,
            prediction,
            risk_score,
            risk_level,
            reasons,
            features,
            scan_date
        )

        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (

        url,

        prediction,

        risk_score,

        risk_level,

        reasons,

        features,

        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    ))


    connection.commit()


    scan_id = cursor.lastrowid


    connection.close()


    return scan_id


# --------------------------------
# Get all scans
# --------------------------------

def get_all_scans():

    connection = get_connection()

    cursor = connection.cursor()


    cursor.execute("""
        SELECT *
        FROM scan_history
        ORDER BY id DESC
    """)


    scans = cursor.fetchall()


    connection.close()


    return scans


# --------------------------------
# Get statistics
# --------------------------------

def get_statistics():

    connection = get_connection()

    cursor = connection.cursor()


    # Total scans

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM scan_history
    """)

    total_scans = cursor.fetchone()["total"]


    # Phishing scans

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM scan_history
        WHERE prediction = 'PHISHING'
    """)

    phishing_scans = cursor.fetchone()["total"]


    # Legitimate scans

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM scan_history
        WHERE prediction = 'LEGITIMATE'
    """)

    legitimate_scans = cursor.fetchone()["total"]


    # Average risk

    cursor.execute("""
        SELECT AVG(risk_score) AS average_risk
        FROM scan_history
    """)

    result = cursor.fetchone()


    average_risk = result["average_risk"]


    if average_risk is None:

        average_risk = 0


    connection.close()


    return {

        "total_scans": total_scans,

        "phishing_scans": phishing_scans,

        "legitimate_scans":
            legitimate_scans,

        "average_risk":
            round(average_risk, 2)

    }
# --------------------------------
# Get one scan by ID
# --------------------------------

def get_scan_by_id(scan_id):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scan_history
        WHERE id = ?
    """, (scan_id,))

    scan = cursor.fetchone()

    connection.close()

    return scan