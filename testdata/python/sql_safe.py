from flask import request
import sqlite3

def get_user():
    username = request.form["username"]
    conn = sqlite3.connect("db.sqlite")
    conn.execute("SELECT * FROM users WHERE name = ?", (username,))
