import mysql.connector as mc

conn = mc.connect(
    host="127.0.0.1",   # important on Windows
    port=3306,
    user="team404user",
    password="pass",
    database="team404",
)
print("Connected?", conn.is_connected())
conn.close()