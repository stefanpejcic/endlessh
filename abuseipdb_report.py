import sqlite3
import requests
import yaml
import datetime

CONFIG_FILE = 'config.yaml'
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/report'

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def report_ip_to_abuseipdb(ip_address, comment, api_key, categories=[15]):
    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }
    data = {
        'ip': ip_address,
        'categories': ','.join(str(c) for c in categories),
        'comment': comment,
    }
    response = requests.post(ABUSEIPDB_URL, headers=headers, data=data)
    if response.status_code == 200:
        print(f"Reported IP {ip_address} successfully.")
    else:
        print(f"Failed to report IP {ip_address}: {response.status_code} {response.text}")

def main():
    config = load_config()
    db_file = config['db_file']
    api_key = config['abuseipdb_api_key']

    if not api_key:
        print("Error: AbuseIPDB API key is missing in config.yaml")
        return

    today = datetime.date.today().isoformat()  # e.g. '2025-07-08'

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT DISTINCT ip_address, created_at 
            FROM sessions 
            WHERE date(created_at) = ?
        """, (today,))

        rows = cursor.fetchall()

        for ip, created_at in rows:
            comment = f"SSH brute force attempt detected. Time: {created_at}"
            report_ip_to_abuseipdb(ip, comment, api_key)

if __name__ == '__main__':
    main()
