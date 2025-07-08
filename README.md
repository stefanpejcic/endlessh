# 🐍 Endlessh

A Python-based SSH tarpit that slows down brute-force bots by feeding them random SSH banners very slowly.

Heavily inpired by [skeeto/endlessh](https://github.com/skeeto/endlessh/tree/master)

## Features

- Asyncio-based scalable server
- Logs all IP connections to a file ao you can review, block, add to blacklist, etc.
- Sends random SSH banners
- Configurable min/max delays
- Docker of course

## Usage

build:
```
docker build -t endlessh-python .
```

then run:
```
docker run -d -p 2222:2222 --name endlessh endlessh
```

You can map to port 22 if you're not running a real SSH server: `-p 22:2222`
