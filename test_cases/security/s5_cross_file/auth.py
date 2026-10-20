import sqlite3


def find_user(username):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    query = "SELECT id, name FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
