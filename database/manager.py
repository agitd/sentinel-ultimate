import sqlite3
import platform
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from config.settings import DB_FILE

logger = logging.getLogger(__name__)

class ScanDatabase:
    def __init__(self, db_file: str = DB_FILE) -> None:
        self.db_file = db_file
        self.init_db()

    def init_db(self) -> None:
        """Инициализация таблиц базы данных"""
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS scans
                (id INTEGER PRIMARY KEY AUTOINCREMENT, subnet TEXT, timestamp DATETIME,
                os_platform TEXT, total_found INTEGER)''')
            c.execute('''CREATE TABLE IF NOT EXISTS hosts
                (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ip TEXT,
                hostname TEXT, ports TEXT, os_guess TEXT, confidence INTEGER,
                FOREIGN KEY(scan_id) REFERENCES scans(id))''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database init error: {e}")

    def save_scan(self, subnet: str, results: List[Dict]) -> Optional[int]:
        """Сохранение результатов сканирования"""
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            timestamp = datetime.now().isoformat()
            c.execute('''INSERT INTO scans (subnet, timestamp, os_platform, total_found)
                         VALUES (?, ?, ?, ?)''', (subnet, timestamp, platform.system(), len(results)))
            scan_id = c.lastrowid
            for r in results:
                c.execute('''INSERT INTO hosts (scan_id, ip, hostname, ports, os_guess, confidence)
                             VALUES (?, ?, ?, ?, ?, ?)''',
                          (scan_id, r['ip'], r.get('name', 'unk'), r['ports'], r['os'], 0))
            conn.commit()
            conn.close()
            print(f"[+] Scan saved to database (ID: {scan_id})")
            return scan_id
        except Exception as e:
            logger.error(f"Error saving scan: {e}")
            return None

    def get_scan_history(self) -> List[Tuple]:
        """МЕТОД: получение истории всех сканирований"""
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('SELECT id, subnet, timestamp, total_found FROM scans ORDER BY id DESC')
            res = c.fetchall()
            conn.close()
            return res
        except Exception as e:
            logger.error(f"History Error: {e}")
            return []

    def compare_scans(self, subnet: str) -> Optional[Dict]:
        """Сравнение текущего сканирования с предыдущим для этой же сети"""
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('SELECT id FROM scans WHERE subnet = ? ORDER BY id DESC LIMIT 2', (subnet,))
            scan_ids = [row[0] for row in c.fetchall()]
            if len(scan_ids) < 2:
                conn.close()
                return None

            latest_id, previous_id = scan_ids[0], scan_ids[1]

            c.execute('SELECT ip, ports FROM hosts WHERE scan_id = ?', (latest_id,))
            latest = {row[0]: row[1] for row in c.fetchall()}

            c.execute('SELECT ip, ports FROM hosts WHERE scan_id = ?', (previous_id,))
            previous = {row[0]: row[1] for row in c.fetchall()}

            conn.close()

            return {
                'new': set(latest.keys()) - set(previous.keys()),
                'gone': set(previous.keys()) - set(latest.keys()),
                'changed': {ip for ip in set(latest.keys()) & set(previous.keys()) if latest.get(ip) != previous.get(ip)}
            }
        except Exception as e:
            logger.error(f"Error comparing scans: {e}")
            return None

