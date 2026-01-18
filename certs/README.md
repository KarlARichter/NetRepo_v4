This folder stores TLS certificates for local development.

This project includes a *self-signed localhost certificate* (server.crt / server.key) so TLS works out-of-the-box.

Security note:
- These files are **development-only**.
- Never reuse or commit private keys for real deployments.

To regenerate a new cert/key on your machine:
- scripts/generate_certs.sh (macOS/Linux)
- scripts/generate_certs.ps1 (Windows + OpenSSL on PATH)
