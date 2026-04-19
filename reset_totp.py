import sqlite3, os

# Remove secret file
try:
    os.remove('/data/totp-secret.txt')
    print('Secret file removed')
except FileNotFoundError:
    print('Secret file already gone')

# Clear setup flag
con = sqlite3.connect('/data/uptime.db')
con.execute("DELETE FROM meta WHERE key='totp_setup_complete'")
con.commit()
con.close()
print('Setup flag cleared — restart container to generate new secret')
