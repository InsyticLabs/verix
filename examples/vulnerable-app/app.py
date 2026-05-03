from __future__ import annotations

import sqlite3

API_KEY = "example-api-key-placeholder"


def search_users(query: str) -> list[dict]:
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    cursor.execute(sql)
    return [dict(row) for row in cursor.fetchall()]


def run_command(user_input: str) -> None:
    eval(user_input)
