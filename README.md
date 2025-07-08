# 🐍 Endlessh

A containerized SSH honeypot that traps brute-force bots by slowly feeding them randomized SSH banners, delaying their attacks and gathering data.

* Sends authentic SSH banners, custom messages, or random gibberish
* Detects and analyzes attack patterns
* Generates detailed summary reports
* Exports data in TXT, JSON formats, or directly to AbuseIPDB API



## Usage

### 1. Start the container

```
docker compose up --build -d
```

### 2. Generate Report

```bash
docker exec endleshh -it python endlessh.py report
```

Output example:
```bash
# ============================================================
#            SSH HONEYPOT ATTACK ANALYSIS REPORT
# ============================================================
# 
# 📊 OVERVIEW:
#    Total Sessions: 156
#    Total Auth Attempts: 487
#    Unique IP Addresses: 42
#    Average Session Duration: 45.3s
#    Longest Session: 312.7s
# 
# 🎯 TOP ATTACKING IPs:
#    192.168.1.100   -  23 attempts
#    10.0.0.45       -  18 attempts
#    172.16.0.33     -  15 attempts
# 
# 👤 MOST COMMON USERNAMES:
#    admin           -  89 attempts
#    root            -  67 attempts
#    user            -  34 attempts
# 
# 🔐 MOST COMMON PASSWORDS:
#    123456          -  45 attempts
#    password        -  38 attempts
#    admin           -  29 attempts
# 
# 🚨 ATTACK PATTERNS:
#    brute_force     -  23 incidents (severity: 8.2)
#    dictionary_attack -  18 incidents (severity: 7.1)
#    rapid_connections -  12 incidents (severity: 8.9)
```

### 3. Real-time Monitoring

Monitor activity every 5 seconds:
```bash
docker exec endleshh -it python endleshh.py monitor
```

Monitor with custom interval (10 seconds):
```bash
docker exec endleshh -it python endleshh.py monitor 10
```

Output example:
```bash
# Real-time monitoring started (Press Ctrl+C to stop)
# --------------------------------------------------
# 
# [14:25:30] New Activity:
#   🔗 New session: 192.168.1.100
#   🔐 Auth attempt: 192.168.1.100 - admin:password123
#   🔐 Auth attempt: 192.168.1.100 - root:admin
#   🚨 Attack pattern: 192.168.1.100 - brute_force
```

### 4. Export Data

Export to default file (attack_data.json):
```bash
docker exec endleshh -it python endlessh.py export
```

Export to custom file:
```bash
docker exec endleshh -it python endleshh.py export my_attack_data.json
```

Export to TXT file for any blacklist:
```bash
docker exec endleshh -it python export_to_blacklist.py
```

### 5. Report to AbuseIPDB

To automatically report all IPs to AbuseIPDB you need to setup api key in config.yaml:
```bash
abuseipdb_api_key: "IMSERT YOUR API KEY HERE"
```
and then configure a cron to run it daily:
```bash
30 23 * * * docker exec endleshh /usr/bin/python3 report_abuseipdb.py
```


## Attack Pattern Detection

These attack patterns are currently detected:

1. **Brute Force** (severity: 8)
   - Multiple authentication attempts in single session
   - Triggers when ≥3 authentication attempts

2. **Dictionary Attack** (severity: 7)
   - Use of common passwords
   - Triggers when ≥2 common passwords used

3. **Username Enumeration** (severity: 6)
   - Attempting suspicious usernames
   - Triggers when ≥2 suspicious usernames used

4. **Rapid Connections** (severity: 9)
   - Multiple connections from same IP
   - Triggers when ≥5 connections in 1 hour

5. **Long Session** (severity: 4)
   - Unusually long session duration
   - Triggers when session >5 minutes

## Fake Shell Commands

The honeypot simulates these shell commands:

- `whoami` - Returns "user"
- `pwd` - Returns current directory
- `ls` - Lists fake files
- `ps` / `ps aux` - Shows fake processes
- `uname -a` - Shows fake system info
- `cat /etc/passwd` - Shows fake user accounts
- `ifconfig` / `ip addr` - Shows fake network config
- `netstat -an` - Shows fake network connections
- `cd` - Changes fake directory
- `history` - Shows fake command history
- `exit` / `logout` - Closes session


## Log Files

These logs are generated:

- `connections.log` - Standard connection logs
- `honeypot.db` - SQLite database with detailed attack data
- Console output/docker log - Real-time activity information


## Performance Tuning

For high-traffic environments I recommend:

1. Adjusting `min_delay` and `max_delay` for faster responses
2. Reducing `session_timeout` for resource management


## Troubleshooting

Common issues and solutions:

1. **Port already in use**: Change the port in config.yaml
2. **Database locked**: Ensure only one instance is running
3. **High CPU usage**: Increase delays or implement rate limiting
4. **Permission denied**: Ensure proper file permissions

## Credits

Heavily inpired by [skeeto/endlessh](https://github.com/skeeto/endlessh/tree/master)

## TODO

1. **New Attack Patterns**: Add detection logic to `AttackPatternDetector`
2. **More Shell Commands**: Extend `FakeShellHandler`
3. **Protocol Support**: Enhance `SSHProtocolHandler`
4. **Custom Responses**: Modify response generation logic
5. **Integration**: Add webhooks or API endpoints
6. **IP Limiting**: Implement connection limits per IP
7. **DB Improvements** - Use database connection pooling and async database operations

