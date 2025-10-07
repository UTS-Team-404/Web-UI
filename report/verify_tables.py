import mysql.connector as mc
cfg = dict(host="127.0.0.1", port=3306, user="team404user", password="pass", database="team404")
cn = mc.connect(**cfg); cur = cn.cursor()
cur.execute("SHOW TABLES")
print([r[0] for r in cur.fetchall()])
cur.close(); cn.close()
