# src/db.py
import sqlite3
import time

class ThreatDB:
    def __init__(self, db_path='threats.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_table()

    def _create_table(self):
        c = self.conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src TEXT,
                dst TEXT,
                reason TEXT,
                score REAL
            )
        ''')
        self.conn.commit()

    def insert_alert(self, src, dst, reason, score):
        t = time.time()
        c = self.conn.cursor()
        c.execute('INSERT INTO alerts (timestamp, src, dst, reason, score) VALUES (?,?,?,?)',
                  (t, src, dst, reason, score))
        self.conn.commit()
