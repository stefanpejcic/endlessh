#!/usr/bin/env python3
import asyncio
import random
import string
import logging
import yaml
from datetime import datetime
from collections import defaultdict

CONFIG_PATH = "config.yaml"

# Load config
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

# Configuration
HOST = config.get("host", "0.0.0.0")
PORT = config.get("port", 2222)
MIN_DELAY = config.get("min_delay", 0.5)
MAX_DELAY = config.get("max_delay", 1.5)
LOG_FILE = config.get("log_file", "connections.log")
BANNERS_FILE = config.get("banners_file", "banners.txt")
MODE = config.get("mode", "mixed")
GIBBERISH_LEN = config.get("gibberish_length", 30)
CHUNK_SIZE = config.get("chunk_size", 1)
MAX_BYTES = config.get("max_bytes", None)
INITIAL_DELAY_RANGE = config.get("initial_delay_range", [0.0, 1.5])

# Load banners
try:
    with open(BANNERS_FILE, "r") as f:
        BANNERS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    BANNERS = ["SSH-2.0-OpenSSH_8.2p1"]

# Setup logging
log_queue = asyncio.Queue()
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

async def log_writer():
    while True:
        msg = await log_queue.get()
        logging.info(msg)

def generate_gibberish(length):
    chars = string.ascii_letters + string.digits + string.punctuation
    gibberish = ''.join(random.choices(chars, k=length))

    # Add optional noise (newlines, etc.)
    if random.random() < 0.3:
        insert_pos = random.randint(1, len(gibberish) - 1)
        gibberish = gibberish[:insert_pos] + "\n" + gibberish[insert_pos:]
    return gibberish + "\r\n"

def get_banner():
    if MODE == "normal":
        return random.choice(BANNERS) + "\r\n"
    elif MODE == "gibberish":
        return generate_gibberish(GIBBERISH_LEN)
    elif MODE == "mixed":
        if random.random() < 0.5:
            return random.choice(BANNERS) + "\r\n"
        else:
            return generate_gibberish(GIBBERISH_LEN)
    else:
        return random.choice(BANNERS) + "\r\n"

async def slow_send(writer, text, min_delay, max_delay, chunk_size=1):
    await asyncio.sleep(random.uniform(*INITIAL_DELAY_RANGE))
    sent = 0
    for i in range(0, len(text), chunk_size):
        if MAX_BYTES is not None and sent >= MAX_BYTES:
            break
        chunk = text[i:i+chunk_size]
        writer.write(chunk.encode(errors="ignore"))
        await writer.drain()
        await asyncio.sleep(random.uniform(min_delay, max_delay))
        sent += len(chunk)

async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    ip = addr[0] if addr else "unknown"
    await log_queue.put(f"Connection from {ip}")
    print(f"[+] {ip} connected")

    banner = get_banner()
    try:
        await slow_send(writer, banner, MIN_DELAY, MAX_DELAY, CHUNK_SIZE)
    except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[-] {ip} disconnected")

async def main():
    # Start async log writer
    asyncio.create_task(log_writer())

    # Start server
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = server.sockets[0].getsockname()
    print(f"[*] Serving on {addr} (mode: {MODE})")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Exiting.")
    
