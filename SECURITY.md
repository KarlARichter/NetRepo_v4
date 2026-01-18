# SECURITY / Threat Model (High-level)

## Assets
- Credentials (username/password)
- Repository files (confidentiality + integrity)
- Server availability

## Threats considered
1. **Credential theft in transit**
   - Mitigation: TLS (`--tls`) encrypts credentials and file data over the wire.

2. **Directory traversal / unauthorized file access**
   - Mitigation: strict filename validation + safe path join prevents `../` escapes and path separators.

3. **File tampering**
   - Mitigation: server provides SHA-256 hash for downloads; client verifies before saving/printing.

4. **Brute-force login attempts**
   - Mitigation: bcrypt hashes slow offline guessing; rate limiting reduces online abuse.
   - Future: add account lockouts + exponential backoff per user.

5. **Denial of Service via oversized messages**
   - Mitigation: hard caps on message size and file size; socket timeouts; rate limiting.

## Security limitations (for transparency)
- Uses a self-signed certificate for localhost development.
- File transfers are base64-encoded inside JSON (OK for small files; not optimal for large files).
- No MFA; no password policy enforcement beyond length validation (future work).
