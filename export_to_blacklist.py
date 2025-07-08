import sqlite3
import yaml
import datetime

CONFIG_FILE = 'config.yaml'

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def main():
    config = load_config()
    db_file = config['db_file']
    rbl_file = config.get('rbl_file', 'last_7_days_ips.txt')
    rbl_days_period = config.get('rbl_days_period', 7)  # default to 7 if missing

    cutoff_date = (datetime.date.today() - datetime.timedelta(days=rbl_days_period)).isoformat()

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT ip_address 
            FROM sessions 
            WHERE date(created_at) >= ?
        """, (cutoff_date,))
        ips = [row[0] for row in cursor.fetchall()]

    with open(rbl_file, 'w') as f:
        for ip in ips:
            f.write(ip + '\n')

    print(f"Wrote {len(ips)} IPs from last {rbl_days_period} days to {rbl_file}")

if __name__ == '__main__':
    main()
  
