# 🐍 Endlessh

A Python-based SSH tarpit that slows down brute-force bots by feeding them random SSH banners very slowly.

Heavily inpired by [skeeto/endlessh](https://github.com/skeeto/endlessh/tree/master)


## Usage

### 1. Start the Honeypot Server

```
docker compose up --build -d
```

### 2. Generate Attack Analysis Report

```bash
docker exec endleshh -it python honeypot.py report
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
docker exec endleshh -it python honeypot.py monitor
```

Monitor with custom interval (10 seconds):
```bash
docker exec endleshh -it python honeypot.py monitor 10
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

### 4. Export Attack Data

Export to default file (attack_data.json):
```bash
docker exec endleshh -it python honeypot.py export
```

Export to custom file:
```bash
docker exec endleshh -it python honeypot.py export my_attack_data.json
```

## Database Schema

The honeypot creates the following SQLite tables:

### Sessions Table
- `id` - Unique session identifier
- `ip_address` - Client IP address
- `start_time` - Session start timestamp
- `end_time` - Session end timestamp
- `duration` - Session duration in seconds
- `fingerprint` - SSH client fingerprint (JSON)

### Auth Attempts Table
- `session_id` - References sessions.id
- `ip_address` - Client IP address
- `username` - Attempted username
- `password` - Attempted password
- `method` - Authentication method
- `success` - Authentication success (always false)
- `timestamp` - Attempt timestamp

### Commands Table
- `session_id` - References sessions.id
- `command` - Command executed in fake shell
- `timestamp` - Command execution timestamp

### Attack Patterns Table
- `ip_address` - Client IP address
- `pattern_type` - Type of attack pattern
- `description` - Pattern description
- `severity` - Severity level (1-10)
- `first_seen` - First occurrence timestamp
- `last_seen` - Last occurrence timestamp
- `occurrence_count` - Number of occurrences

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


## TODO

1. **New Attack Patterns**: Add detection logic to `AttackPatternDetector`
2. **More Shell Commands**: Extend `FakeShellHandler`
3. **Protocol Support**: Enhance `SSHProtocolHandler`
4. **Custom Responses**: Modify response generation logic
5. **Integration**: Add webhooks or API endpoints
6. **IP Limiting**: Implement connection limits per IP
7. **DB Improvements** - Use database connection pooling and async database operations

