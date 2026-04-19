import sqlite3, time

# Set this to when you FIRST started the container (days ago)
# Change the number below — e.g. 2.5 means 2.5 days ago
DAYS_AGO = 2.5

created_at = int(time.time()) - int(DAYS_AGO * 86400)

con = sqlite3.connect('/data/uptime.db')
con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
# Force overwrite with correct time
con.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('created_at',?)", (str(created_at),))
con.commit()

cur = con.cursor()
cur.execute("SELECT key, value, datetime(CAST(value AS INTEGER), 'unixepoch') FROM meta")
for row in cur.fetchall():
    print(row)
con.close()
print("Done — restart the container to see updated uptime %")
