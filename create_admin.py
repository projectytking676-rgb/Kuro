import os
import getpass
from werkzeug.security import generate_password_hash
from app import db, init_db

init_db()
username = input("Admin username: ").strip()
password = getpass.getpass("Admin password (12+ characters): ")
if len(username) < 3 or len(password) < 12:
    raise SystemExit("Username must be 3+ chars and password 12+ chars.")
with db() as con:
    con.execute(
        "INSERT INTO admins(username,password_hash) VALUES(?,?)",
        (username, generate_password_hash(password))
    )
print("Admin account created.")
