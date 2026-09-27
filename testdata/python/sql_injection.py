from flask import request
import sqlite3

def get_user():
    username = request.form["username"]
    query = f"SELECT * FROM users WHERE name = '{username}'"
    conn = sqlite3.connect("db.sqlite")
    conn.execute(query)
