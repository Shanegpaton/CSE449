import sqlite3


def orders_for(customer_id):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, total FROM orders WHERE customer_id = ?", (customer_id,))
    return cursor.fetchall()
