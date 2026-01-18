# NetRepo Secure

A secure, multithreaded TCP file repository service (client + server) built in Python.

## What this adds vs. a basic socket assignment
- **Length-prefixed JSON protocol** (reliable message framing; avoids EOF-marker pitfalls)
- **Authentication & RBAC** using **bcrypt** (user/admin roles)
- **TLS encryption in transit** using Python `ssl` (recommended)
- **Directory traversal protection** for filenames
- **SHA-256 integrity verification** for downloaded files
- **Rate limiting** (token bucket) to reduce abuse / DoS risk
- **Audit logging** with rotating log files

## Quick Start

### 1) Install dependencies
```bash
pip install -r requirements.txt
```

### 2) Generate a local TLS certificate (recommended)
Generate a self-signed cert for localhost in `certs/` (keys are not committed).
```bash
bash scripts/generate_certs.sh
# or on Windows PowerShell:
# .\scripts\generate_certs.ps1
```

### 3) Start the server
**With TLS (recommended):**
```bash
python server.py --tls
```

**Without TLS (dev only):**
```bash
python server.py
```

### 4) Start the client
**With TLS (recommended):**
```bash
python client.py --tls
```

**Without TLS:**
```bash
python client.py
```

## Default demo credentials (change these)
- `admin / admin123!` (role: admin)
- `user  / user123!`  (role: user)

Use:
- `ADDUSER <u> <p> <role>` (admin)
- `CHPASS <u> <newp>` (admin)

## Commands
- `HELP`
- `LOGIN <username> <password>`
- `LIST`
- `GET <filename>` (alias: `PRINT <filename>`)
- `STATUS` (admin)
- `LOGOUT`
- `QUIT`

## Repo folder
The server serves files from `./repo/`. Add test files there.

## Notes
This project is designed for learning and portfolio demonstration. For real production usage,
you would add stronger secrets management, account lockouts, structured telemetry, and streaming
file transfers instead of base64-in-JSON for large files.
