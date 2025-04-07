import sqlite3

def init_db():
    conn = sqlite3.connect("packets.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS traffic (
                timestamp TEXT,
                protocol TEXT,
                src TEXT,
                dst TEXT,
                length INTEGER)""")
    conn.commit()
    conn.close()

def insert_packet(data):
    conn = sqlite3.connect("packets.db")
    c = conn.cursor()
    c.execute("INSERT INTO traffic VALUES (?, ?, ?, ?, ?)",
              (data['timestamp'], data['protocol'], data['src'], data['dst'], data['length']))
    conn.commit()
    conn.close()
