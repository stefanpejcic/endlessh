#!/usr/bin/env python3
"""
SSH Honeypot Server - Captures authentication attempts, commands, and analyzes attack patterns
"""

import sys
import asyncio
import random
import string
import logging
import yaml
import json
import hashlib
import time
import re
from datetime import datetime, timedelta
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, Counter
import sqlite3
import threading


@dataclass
class HoneypotConfig:
    """Configuration class for the honeypot server"""
    host: str = "0.0.0.0"
    port: int = 2222
    min_delay: float = 0.1
    max_delay: float = 0.3
    log_file: str = "connections.log"
    db_file: str = "honeypot.db"
    banners_file: str = "banners.txt"
    mode: str = "mixed"  # normal, gibberish, or mixed
    gibberish_length: int = 30
    chunk_size: int = 1
    max_bytes: Optional[int] = None
    initial_delay_range: Tuple[float, float] = (0.0, 0.5)
    max_auth_attempts: int = 3
    session_timeout: int = 300  # 5 minutes
    enable_fake_shell: bool = True


@dataclass
class SSHClientFingerprint:
    """SSH client fingerprint data"""
    client_version: str
    kex_algorithms: List[str] = None
    server_host_key_algorithms: List[str] = None
    encryption_algorithms: List[str] = None
    mac_algorithms: List[str] = None
    compression_algorithms: List[str] = None
    first_kex_packet_follows: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthAttempt:
    """Authentication attempt data"""
    timestamp: datetime
    ip_address: str
    username: str
    password: str
    method: str
    success: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class SessionInfo:
    """Session information"""
    session_id: str
    ip_address: str
    start_time: datetime
    end_time: Optional[datetime] = None
    auth_attempts: List[AuthAttempt] = None
    commands: List[str] = None
    fingerprint: Optional[SSHClientFingerprint] = None
    
    def __post_init__(self):
        if self.auth_attempts is None:
            self.auth_attempts = []
        if self.commands is None:
            self.commands = []
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()


class DatabaseManager:
    """Handles database operations for the honeypot"""
    
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    duration REAL,
                    fingerprint TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    method TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL,
                    occurrence_count INTEGER DEFAULT 1
                )
            """)
    
    def save_session(self, session: SessionInfo):
        """Save session to database"""
        with self.lock:
            with sqlite3.connect(self.db_file) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO sessions 
                    (id, ip_address, start_time, end_time, duration, fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    session.session_id,
                    session.ip_address,
                    session.start_time,
                    session.end_time,
                    session.duration,
                    json.dumps(session.fingerprint.to_dict()) if session.fingerprint else None
                ))
                
                # Save auth attempts
                for auth in session.auth_attempts:
                    conn.execute("""
                        INSERT INTO auth_attempts 
                        (session_id, ip_address, username, password, method, success, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        session.session_id,
                        auth.ip_address,
                        auth.username,
                        auth.password,
                        auth.method,
                        auth.success,
                        auth.timestamp
                    ))
                
                # Save commands
                for i, command in enumerate(session.commands):
                    conn.execute("""
                        INSERT INTO commands (session_id, command, timestamp)
                        VALUES (?, ?, ?)
                    """, (
                        session.session_id,
                        command,
                        session.start_time + timedelta(seconds=i)
                    ))
    
    def save_attack_pattern(self, ip_address: str, pattern_type: str, description: str, severity: int):
        """Save attack pattern to database"""
        with self.lock:
            with sqlite3.connect(self.db_file) as conn:
                # Check if pattern already exists
                existing = conn.execute("""
                    SELECT id, occurrence_count FROM attack_patterns 
                    WHERE ip_address = ? AND pattern_type = ? AND description = ?
                """, (ip_address, pattern_type, description)).fetchone()
                
                if existing:
                    # Update existing pattern
                    conn.execute("""
                        UPDATE attack_patterns 
                        SET last_seen = CURRENT_TIMESTAMP, occurrence_count = occurrence_count + 1
                        WHERE id = ?
                    """, (existing[0],))
                else:
                    # Insert new pattern
                    conn.execute("""
                        INSERT INTO attack_patterns 
                        (ip_address, pattern_type, description, severity, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """, (ip_address, pattern_type, description, severity))


class SSHProtocolHandler:
    """Handles SSH protocol simulation and fingerprinting"""
    
    COMMON_SSH_VERSIONS = [
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "SSH-2.0-OpenSSH_7.4",
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        "SSH-2.0-OpenSSH_8.0",
        "SSH-2.0-libssh_0.8.9",
    ]
    
    def __init__(self):
        self.server_version = random.choice(self.COMMON_SSH_VERSIONS)
    
    def parse_client_version(self, data: bytes) -> Optional[str]:
        """Parse SSH client version from initial data"""
        try:
            text = data.decode('utf-8', errors='ignore')
            if text.startswith('SSH-'):
                return text.strip()
        except:
            pass
        return None
    
    def parse_kex_init(self, data: bytes) -> Optional[SSHClientFingerprint]:
        """Parse SSH_MSG_KEXINIT packet for client fingerprinting"""
        try:
            # This is a simplified parser - real SSH parsing is more complex
            if len(data) < 20:
                return None
            
            # Skip packet length and padding
            if data[0] == 0x14:  # SSH_MSG_KEXINIT
                return SSHClientFingerprint(
                    client_version="Unknown",
                    kex_algorithms=["diffie-hellman-group14-sha256"],
                    encryption_algorithms=["aes128-ctr"],
                    mac_algorithms=["hmac-sha2-256"]
                )
        except:
            pass
        return None
    
    def generate_server_banner(self) -> str:
        """Generate realistic SSH server banner"""
        return self.server_version + "\r\n"
    
    def generate_kex_init_response(self) -> bytes:
        """Generate SSH_MSG_KEXINIT response"""
        # Simplified KEX_INIT response
        kex_init = bytearray([0x14])  # SSH_MSG_KEXINIT
        kex_init.extend(b'\x00' * 16)  # Random cookie
        
        # Algorithm lists (simplified)
        algorithms = [
            "diffie-hellman-group14-sha256",
            "rsa-sha2-512",
            "aes128-ctr",
            "hmac-sha2-256",
            "none"
        ]
        
        for alg_list in algorithms:
            alg_bytes = alg_list.encode()
            kex_init.extend(len(alg_bytes).to_bytes(4, 'big'))
            kex_init.extend(alg_bytes)
        
        kex_init.extend(b'\x00' * 5)  # Reserved fields
        
        return bytes(kex_init)


class AttackPatternDetector:
    """Detects and analyzes attack patterns"""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.ip_attempts = defaultdict(list)
        self.common_passwords = self._load_common_passwords()
        self.suspicious_usernames = self._load_suspicious_usernames()
    
    def _load_common_passwords(self) -> set:
        """Load common passwords for detection"""
        return {
            "123456", "password", "admin", "root", "12345678",
            "qwerty", "123456789", "letmein", "1234567890",
            "football", "iloveyou", "admin123", "welcome",
            "monkey", "login", "abc123", "starwars", "123123",
            "dragon", "passw0rd", "master", "hello", "freedom"
        }
    
    def _load_suspicious_usernames(self) -> set:
        """Load suspicious usernames for detection"""
        return {
            "admin", "administrator", "root", "user", "test",
            "guest", "oracle", "postgres", "mysql", "ftpuser",
            "www", "mail", "email", "operator", "manager",
            "service", "support", "supervisor", "controller"
        }
    
    def analyze_session(self, session: SessionInfo):
        """Analyze session for attack patterns"""
        ip = session.ip_address
        
        # Pattern 1: Brute force detection
        if len(session.auth_attempts) >= 3:
            self.db_manager.save_attack_pattern(
                ip, "brute_force", 
                f"Multiple authentication attempts: {len(session.auth_attempts)}", 
                8
            )
        
        # Pattern 2: Dictionary attack detection
        passwords_used = [auth.password for auth in session.auth_attempts]
        common_used = sum(1 for p in passwords_used if p in self.common_passwords)
        if common_used >= 2:
            self.db_manager.save_attack_pattern(
                ip, "dictionary_attack",
                f"Used {common_used} common passwords",
                7
            )
        
        # Pattern 3: Username enumeration
        usernames_used = set(auth.username for auth in session.auth_attempts)
        suspicious_users = usernames_used & self.suspicious_usernames
        if len(suspicious_users) >= 2:
            self.db_manager.save_attack_pattern(
                ip, "username_enumeration",
                f"Attempted suspicious usernames: {', '.join(suspicious_users)}",
                6
            )
        
        # Pattern 4: Rapid connection attempts
        self.ip_attempts[ip].append(session.start_time)
        recent_attempts = [
            t for t in self.ip_attempts[ip] 
            if (session.start_time - t).total_seconds() < 3600  # Last hour
        ]
        
        if len(recent_attempts) >= 5:
            self.db_manager.save_attack_pattern(
                ip, "rapid_connections",
                f"Rapid connection attempts: {len(recent_attempts)} in last hour",
                9
            )
        
        # Pattern 5: Long session duration (potential manual analysis)
        if session.duration > 300:  # 5 minutes
            self.db_manager.save_attack_pattern(
                ip, "long_session",
                f"Session duration: {session.duration:.1f} seconds",
                4
            )


class FakeShellHandler:
    """Simulates a fake shell environment"""
    
    def __init__(self):
        self.current_dir = "/home/user"
        self.fake_files = {
            "/": ["bin", "etc", "home", "usr", "var", "tmp"],
            "/home": ["user"],
            "/home/user": ["documents", "downloads", ".ssh", ".bash_history"],
            "/etc": ["passwd", "shadow", "hosts", "ssh"],
        }
        self.fake_processes = [
            "systemd", "kthreadd", "ksoftirqd", "migration", "sshd",
            "apache2", "mysql", "nginx", "cron", "openpanel", "dbus"
        ]
    
    def process_command(self, command: str) -> str:
        """Process shell command and return fake output"""
        cmd = command.strip().lower()
        
        if cmd == "":
            return ""
        elif cmd == "whoami":
            return "user"
        elif cmd == "pwd":
            return self.current_dir
        elif cmd.startswith("ls"):
            return self._handle_ls(cmd)
        elif cmd == "ps" or cmd == "ps aux":
            return self._handle_ps()
        elif cmd == "uname -a":
            return "Linux honeypot 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"
        elif cmd == "cat /etc/passwd":
            return self._handle_passwd()
        elif cmd == "ifconfig" or cmd == "ip addr":
            return self._handle_ifconfig()
        elif cmd == "netstat -an":
            return self._handle_netstat()
        elif cmd.startswith("cat"):
            return f"cat: {cmd.split()[1] if len(cmd.split()) > 1 else 'file'}: No such file or directory"
        elif cmd.startswith("cd"):
            return self._handle_cd(cmd)
        elif cmd == "history":
            return self._handle_history()
        elif cmd == "exit" or cmd == "logout":
            return "logout"
        else:
            return f"bash: {cmd}: command not found"
    
    def _handle_ls(self, cmd: str) -> str:
        """Handle ls command"""
        files = self.fake_files.get(self.current_dir, ["file1.txt", "file2.txt"])
        return "\n".join(files)
    
    def _handle_ps(self) -> str:
        """Handle ps command"""
        output = ["USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
        for i, proc in enumerate(self.fake_processes[:10]):
            output.append(f"root      {1000+i}  0.0  0.1  {random.randint(1000,9999)}  {random.randint(100,999)} ?        S    12:00   0:00 {proc}")
        return "\n".join(output)
    
    def _handle_passwd(self) -> str:
        """Handle /etc/passwd"""
        return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash"""
    
    def _handle_ifconfig(self) -> str:
        """Handle ifconfig command"""
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)"""
    
    def _handle_netstat(self) -> str:
        """Handle netstat command"""
        return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN"""
    
    def _handle_cd(self, cmd: str) -> str:
        """Handle cd command"""
        parts = cmd.split()
        if len(parts) > 1:
            new_dir = parts[1]
            if new_dir == "..":
                if self.current_dir != "/":
                    self.current_dir = "/".join(self.current_dir.split("/")[:-1]) or "/"
            elif new_dir.startswith("/"):
                self.current_dir = new_dir
            else:
                self.current_dir = f"{self.current_dir}/{new_dir}".replace("//", "/")
        else:
            self.current_dir = "/home/user"
        return ""
    
    def _handle_history(self) -> str:
        """Handle history command"""
        return """    1  ls -la
    2  cd /var/log
    3  cat auth.log
    4  ps aux | grep ssh
    5  netstat -an
    6  whoami
    7  uname -a
    8  history"""


class HoneypotSession:
    """Manages individual honeypot sessions"""
    
    def __init__(self, session_id: str, ip_address: str, config: HoneypotConfig, 
                 db_manager: DatabaseManager, pattern_detector: AttackPatternDetector):
        self.session = SessionInfo(session_id, ip_address, datetime.now())
        self.config = config
        self.db_manager = db_manager
        self.pattern_detector = pattern_detector
        self.ssh_handler = SSHProtocolHandler()
        self.shell_handler = FakeShellHandler()
        self.authenticated = False
        self.auth_attempts = 0
        
    async def handle_ssh_negotiation(self, reader: asyncio.StreamReader, 
                                   writer: asyncio.StreamWriter) -> bool:
        """Handle SSH protocol negotiation"""
        try:
            # Send server banner
            banner = self.ssh_handler.generate_server_banner()
            writer.write(banner.encode())
            await writer.drain()
            
            # Read client version
            client_data = await asyncio.wait_for(reader.read(1024), timeout=10)
            client_version = self.ssh_handler.parse_client_version(client_data)
            
            if client_version:
                self.session.fingerprint = SSHClientFingerprint(client_version)
                
                # Simulate key exchange
                kex_response = self.ssh_handler.generate_kex_init_response()
                writer.write(kex_response)
                await writer.drain()
                
                # Read potential KEX_INIT from client
                try:
                    kex_data = await asyncio.wait_for(reader.read(1024), timeout=5)
                    fingerprint = self.ssh_handler.parse_kex_init(kex_data)
                    if fingerprint:
                        self.session.fingerprint = fingerprint
                        self.session.fingerprint.client_version = client_version
                except asyncio.TimeoutError:
                    pass
            
            return True
            
        except Exception as e:
            return False
    
    async def handle_authentication(self, reader: asyncio.StreamReader, 
                                  writer: asyncio.StreamWriter) -> bool:
        """Handle SSH authentication simulation"""
        try:
            while self.auth_attempts < self.config.max_auth_attempts:
                # Send authentication request
                auth_request = b"SSH-2.0-AUTH_REQUEST\r\n"
                writer.write(auth_request)
                await writer.drain()
                
                # Read authentication data
                auth_data = await asyncio.wait_for(reader.read(1024), timeout=30)
                
                # Parse authentication attempt (simplified)
                username, password = self._parse_auth_data(auth_data)
                
                auth_attempt = AuthAttempt(
                    timestamp=datetime.now(),
                    ip_address=self.session.ip_address,
                    username=username,
                    password=password,
                    method="password"
                )
                
                self.session.auth_attempts.append(auth_attempt)
                self.auth_attempts += 1
                
                # Always fail authentication but vary the response
                if self.auth_attempts >= self.config.max_auth_attempts:
                    failure_msg = b"Authentication failed.\r\n"
                    writer.write(failure_msg)
                    await writer.drain()
                    return False
                else:
                    failure_msg = b"Permission denied, please try again.\r\n"
                    writer.write(failure_msg)
                    await writer.drain()
                    
                await asyncio.sleep(random.uniform(0.5, 2.0))
            
            return False
            
        except asyncio.TimeoutError:
            return False
        except Exception as e:
            return False
    
    def _parse_auth_data(self, data: bytes) -> Tuple[str, str]:
        """Parse authentication data (simplified)"""
        try:
            text = data.decode('utf-8', errors='ignore')
            # Simple parsing - in reality, SSH auth is more complex
            if ':' in text:
                parts = text.split(':', 1)
                return parts[0].strip(), parts[1].strip()
            else:
                # Extract readable strings as potential usernames/passwords
                readable = re.findall(r'[a-zA-Z0-9_.-]+', text)
                if len(readable) >= 2:
                    return readable[0], readable[1]
                elif len(readable) == 1:
                    return readable[0], ""
                else:
                    return "unknown", ""
        except:
            return "unknown", ""
    
    async def handle_shell_simulation(self, reader: asyncio.StreamReader, 
                                    writer: asyncio.StreamWriter):
        """Handle fake shell interaction"""
        if not self.config.enable_fake_shell:
            return
            
        try:
            # Send fake shell prompt
            prompt = b"user@honeypot:~$ "
            writer.write(prompt)
            await writer.drain()
            
            while True:
                # Read command
                command_data = await asyncio.wait_for(reader.read(1024), timeout=60)
                command = command_data.decode('utf-8', errors='ignore').strip()
                
                if command:
                    self.session.commands.append(command)
                    
                    # Process command
                    output = self.shell_handler.process_command(command)
                    
                    if command.lower() in ['exit', 'logout']:
                        writer.write(b"Connection closed.\r\n")
                        await writer.drain()
                        break
                    
                    # Send output
                    if output:
                        writer.write(f"{output}\r\n".encode())
                        await writer.drain()
                    
                    # Send next prompt
                    writer.write(prompt)
                    await writer.drain()
                
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            pass
    
    def finalize_session(self):
        """Finalize session and save to database"""
        self.session.end_time = datetime.now()
        self.db_manager.save_session(self.session)
        self.pattern_detector.analyze_session(self.session)


class HoneypotServer:
    """Advanced honeypot server with comprehensive logging and analysis"""
    
    def __init__(self, config: HoneypotConfig):
        self.config = config
        self.db_manager = DatabaseManager(config.db_file)
        self.pattern_detector = AttackPatternDetector(self.db_manager)
        self.server = None
        self.sessions = {}
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(config.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle individual client connections with advanced features"""
        addr = writer.get_extra_info("peername")
        ip = addr[0] if addr else "unknown"
        session_id = hashlib.md5(f"{ip}:{time.time()}".encode()).hexdigest()
        
        self.logger.info(f"New connection from {ip} (session: {session_id})")
        
        session = HoneypotSession(session_id, ip, self.config, self.db_manager, self.pattern_detector)
        self.sessions[session_id] = session
        
        try:
            # SSH Protocol negotiation
            if await session.handle_ssh_negotiation(reader, writer):
                self.logger.info(f"SSH negotiation completed for {ip}")
                
                # Authentication phase
                if await session.handle_authentication(reader, writer):
                    self.logger.info(f"Authentication succeeded for {ip}")
                    await session.handle_shell_simulation(reader, writer)
                else:
                    self.logger.info(f"Authentication failed for {ip} after {len(session.session.auth_attempts)} attempts")
            
        except Exception as e:
            self.logger.error(f"Error handling client {ip}: {e}")
        finally:
            # Clean up
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            
            session.finalize_session()
            del self.sessions[session_id]
            self.logger.info(f"Session {session_id} ended for {ip}")
    
    async def start(self):
        """Start the advanced honeypot server"""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                self.config.host,
                self.config.port
            )
            
            addr = self.server.sockets[0].getsockname()
            self.logger.info(f"Advanced SSH Honeypot started on {addr}")
            print(f"[*] Advanced SSH Honeypot serving on {addr}")
            print(f"[*] Database: {self.config.db_file}")
            print(f"[*] Features: Auth logging, Command tracking, Fingerprinting, Pattern detection")
            
            async with self.server:
                await self.server.serve_forever()
        
        except KeyboardInterrupt:
            self.logger.info("Honeypot shutting down...")
            print("\n[*] Shutting down honeypot...")
        finally:
            if self.server:
                self.server.close()
                await self.server.wait_closed()


def load_config(config_path: str = "config.yaml") -> HoneypotConfig:
    """Load configuration from YAML file"""
    try:
        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f)
        
        return HoneypotConfig(
            host=config_data.get("host", "0.0.0.0"),
            port=config_data.get("port", 2222),
            min_delay=config_data.get("min_delay", 0.1),
            max_delay=config_data.get("max_delay", 0.3),
            log_file=config_data.get("log_file", "connections.log"),
            db_file=config_data.get("db_file", "honeypot.db"),
            banners_file=config_data.get("banners_file", "banners.txt"),
            mode=config_data.get("mode", "mixed"),
            gibberish_length=config_data.get("gibberish_length", 30),
            chunk_size=config_data.get("chunk_size", 1),
            max_bytes=config_data.get("max_bytes", None),
            initial_delay_range=tuple(config_data.get("initial_delay_range", [0.0, 0.5])),
            max_auth_attempts=config_data.get("max_auth_attempts", 3),
            session_timeout=config_data.get("session_timeout", 300),
            enable_fake_shell=config_data.get("enable_fake_shell", True)
        )
    except FileNotFoundError:
        print(f"Config file {config_path} not found, using defaults")
        return HoneypotConfig()


async def main():
    """Main entry point"""
    config = load_config()
    server = HoneypotServer(config)
    await server.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")


# Additional utility functions for analysis and reporting

def generate_attack_report(db_file: str = "honeypot.db") -> Dict[str, Any]:
    """Generate comprehensive attack analysis report"""
    with sqlite3.connect(db_file) as conn:
        conn.row_factory = sqlite3.Row
        
        # Basic statistics
        stats = {}
        
        # Total sessions
        stats['total_sessions'] = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        
        # Total auth attempts
        stats['total_auth_attempts'] = conn.execute("SELECT COUNT(*) FROM auth_attempts").fetchone()[0]
        
        # Unique IPs
        stats['unique_ips'] = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM sessions").fetchone()[0]
        
        # Top attacking IPs
        top_ips = conn.execute("""
            SELECT ip_address, COUNT(*) as attempts 
            FROM auth_attempts 
            GROUP BY ip_address 
            ORDER BY attempts DESC 
            LIMIT 10
        """).fetchall()
        stats['top_attacking_ips'] = [dict(row) for row in top_ips]
        
        # Most common usernames
        top_usernames = conn.execute("""
            SELECT username, COUNT(*) as count 
            FROM auth_attempts 
            GROUP BY username 
            ORDER BY count DESC 
            LIMIT 10
        """).fetchall()
        stats['top_usernames'] = [dict(row) for row in top_usernames]
        
        # Most common passwords
        top_passwords = conn.execute("""
            SELECT password, COUNT(*) as count 
            FROM auth_attempts 
            GROUP BY password 
            ORDER BY count DESC 
            LIMIT 10
        """).fetchall()
        stats['top_passwords'] = [dict(row) for row in top_passwords]
        
        # Attack patterns
        patterns = conn.execute("""
            SELECT pattern_type, COUNT(*) as count, AVG(severity) as avg_severity
            FROM attack_patterns 
            GROUP BY pattern_type 
            ORDER BY count DESC
        """).fetchall()
        stats['attack_patterns'] = [dict(row) for row in patterns]
        
        # Most executed commands
        top_commands = conn.execute("""
            SELECT command, COUNT(*) as count 
            FROM commands 
            GROUP BY command 
            ORDER BY count DESC 
            LIMIT 10
        """).fetchall()
        stats['top_commands'] = [dict(row) for row in top_commands]
        
        # Session duration statistics
        duration_stats = conn.execute("""
            SELECT AVG(duration) as avg_duration, 
                   MAX(duration) as max_duration,
                   MIN(duration) as min_duration
            FROM sessions 
            WHERE duration IS NOT NULL
        """).fetchone()
        if duration_stats:
            stats['session_duration'] = dict(duration_stats)
        
        # Daily activity
        daily_activity = conn.execute("""
            SELECT DATE(start_time) as date, COUNT(*) as sessions
            FROM sessions 
            GROUP BY DATE(start_time)
            ORDER BY date DESC
            LIMIT 30
        """).fetchall()
        stats['daily_activity'] = [dict(row) for row in daily_activity]
        
        return stats


def print_attack_report(db_file: str = "honeypot.db"):
    """Print formatted attack analysis report"""
    report = generate_attack_report(db_file)
    
    print("\n" + "="*60)
    print("           SSH HONEYPOT ATTACK ANALYSIS REPORT")
    print("="*60)
    
    print(f"\n📊 OVERVIEW:")
    print(f"   Total Sessions: {report['total_sessions']}")
    print(f"   Total Auth Attempts: {report['total_auth_attempts']}")
    print(f"   Unique IP Addresses: {report['unique_ips']}")
    
    if 'session_duration' in report:
        duration = report['session_duration']
        print(f"   Average Session Duration: {duration['avg_duration']:.1f}s")
        print(f"   Longest Session: {duration['max_duration']:.1f}s")
    
    print(f"\n🎯 TOP ATTACKING IPs:")
    for ip_data in report['top_attacking_ips'][:5]:
        print(f"   {ip_data['ip_address']:<15} - {ip_data['attempts']:>3} attempts")
    
    print(f"\n👤 MOST COMMON USERNAMES:")
    for user_data in report['top_usernames'][:5]:
        print(f"   {user_data['username']:<15} - {user_data['count']:>3} attempts")
    
    print(f"\n🔐 MOST COMMON PASSWORDS:")
    for pass_data in report['top_passwords'][:5]:
        password = pass_data['password'][:20] + "..." if len(pass_data['password']) > 20 else pass_data['password']
        print(f"   {password:<23} - {pass_data['count']:>3} attempts")
    
    print(f"\n🚨 ATTACK PATTERNS:")
    for pattern in report['attack_patterns']:
        print(f"   {pattern['pattern_type']:<20} - {pattern['count']:>3} incidents (severity: {pattern['avg_severity']:.1f})")
    
    if report['top_commands']:
        print(f"\n💻 MOST EXECUTED COMMANDS:")
        for cmd_data in report['top_commands'][:5]:
            command = cmd_data['command'][:30] + "..." if len(cmd_data['command']) > 30 else cmd_data['command']
            print(f"   {command:<33} - {cmd_data['count']:>3} times")
    
    print(f"\n📅 DAILY ACTIVITY (Last 7 days):")
    for day_data in report['daily_activity'][:7]:
        print(f"   {day_data['date']} - {day_data['sessions']:>3} sessions")
    
    print("\n" + "="*60)


def export_attack_data(db_file: str = "honeypot.db", output_file: str = "attack_data.json"):
    """Export attack data to JSON file"""
    report = generate_attack_report(db_file)
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"Attack data exported to {output_file}")


def monitor_real_time(db_file: str = "honeypot.db", interval: int = 5):
    """Monitor honeypot activity in real-time"""
    import time
    
    print("Real-time monitoring started (Press Ctrl+C to stop)")
    print("-" * 50)
    
    last_check = datetime.now() - timedelta(seconds=interval)
    
    try:
        while True:
            with sqlite3.connect(db_file) as conn:
                conn.row_factory = sqlite3.Row
                
                # Check for new sessions
                new_sessions = conn.execute("""
                    SELECT ip_address, start_time FROM sessions 
                    WHERE start_time > ? 
                    ORDER BY start_time DESC
                """, (last_check,)).fetchall()
                
                # Check for new auth attempts
                new_attempts = conn.execute("""
                    SELECT ip_address, username, password, timestamp FROM auth_attempts 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC
                """, (last_check,)).fetchall()
                
                # Check for new attack patterns
                new_patterns = conn.execute("""
                    SELECT ip_address, pattern_type, description, severity FROM attack_patterns 
                    WHERE last_seen > ? 
                    ORDER BY last_seen DESC
                """, (last_check,)).fetchall()
                
                current_time = datetime.now()
                
                if new_sessions or new_attempts or new_patterns:
                    print(f"\n[{current_time.strftime('%H:%M:%S')}] New Activity:")
                    
                    for session in new_sessions:
                        print(f"  🔗 New session: {session['ip_address']}")
                    
                    for attempt in new_attempts:
                        print(f"  🔐 Auth attempt: {attempt['ip_address']} - {attempt['username']}:{attempt['password']}")
                    
                    for pattern in new_patterns:
                        severity_emoji = "🚨" if pattern['severity'] > 7 else "⚠️" if pattern['severity'] > 5 else "ℹ️"
                        print(f"  {severity_emoji} Attack pattern: {pattern['ip_address']} - {pattern['pattern_type']}")
                
                last_check = current_time
                time.sleep(interval)
                
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


# CLI interface for analysis tools
if __name__ == "__main__" and len(sys.argv) > 1:
    import sys
    
    if sys.argv[1] == "report":
        print_attack_report()
    elif sys.argv[1] == "export":
        output_file = sys.argv[2] if len(sys.argv) > 2 else "attack_data.json"
        export_attack_data(output_file=output_file)
    elif sys.argv[1] == "monitor":
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        monitor_real_time(interval=interval)
    else:
        print("Usage:")
        print("  python honeypot.py           - Start honeypot server")
        print("  python honeypot.py report    - Generate attack report")
        print("  python honeypot.py export [file] - Export attack data to JSON")
        print("  python honeypot.py monitor [interval] - Real-time monitoring")
