#!/usr/bin/env python3
import asyncio
import random
import logging
import yaml
from datetime import datetime

CONFIG_PATH = "config.yaml"

# Load config
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

HOST = config.get("host", "0.0.0.0")
PORT = config.get("port", 2222)
MIN_DELAY = config.get("min_delay", 0.5)
MAX_DELAY = config.get("max_delay", 1.5)
LOG_FILE = config.get("log_file", "connections.log")
BANNERS_FILE = config.get("banners_file", "banners.txt")

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Load banners
with open(BANNERS_FILE, "r") as f:
    BANNERS = [line.strip() for line in f if line.strip()]

async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")
    logging.info(f"Connection from {addr}")
    print(f"[+] {addr} connected")

    banner = random.choice(BANNERS) + "\r\n"
    try:
        for char in banner:
            writer.write(char.encode())
            await writer.drain()
            await asyncio.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    except (ConnectionResetError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[-] {addr} disconnected")

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = server.sockets[0].getsockname()
    print(f"[*] Serving on {addr}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
