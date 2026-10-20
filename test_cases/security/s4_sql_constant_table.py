import sqlite3

AUDIT_TABLE = "audit_log"


def count_audit_rows():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT COUNT(*) FROM {AUDIT_TABLE}"
    cursor.execute(query)
    return cursor.fetchone()[0]
