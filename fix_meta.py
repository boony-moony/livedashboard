import sqlite3
con = sqlite3.connect('/data/uptime.db')
con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
con.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('totp_setup_complete','1')")
con.commit()
con.close()
print('done')
