import mysql.connector as mc
cn = mc.connect(host="127.0.0.1", user="team404user", password="pass", database="team404")
cur = cn.cursor()
cur.execute("SELECT MAX(ID) FROM ProjectDB")
print(cur.fetchone()[0])
cur.close(); cn.close()
