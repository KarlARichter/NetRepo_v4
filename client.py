"""
NetRepo Secure - Client
Interactive CLI client for the NetRepo Secure server.

Aliases to match the original assignment feel:
- "list" -> LIST
- "print <filename>" -> PRINT <filename> (downloads + prints if text)

Tips:
- Use TLS if server started with --tls (recommended).
"""

from __future__ import annotations

import argparse
import base64
import os
import ssl
import socket
from typing import List, Tuple

from protocol import send_json, recv_json, ProtocolError
from security import sha256_bytes


DOWNLOADS_DIR_DEFAULT = os.path.join(os.path.dirname(__file__), "downloads")
CERT_DEFAULT = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
SOCKET_TIMEOUT_SEC = 600


def _make_socket(host: str, port: int, tls: bool, cafile: str) -> socket.socket:
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(SOCKET_TIMEOUT_SEC)
    raw.connect((host, port))

    if not tls:
        return raw

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # For a self-signed cert, we pin the server cert as a CA for local dev
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=cafile)
    return ctx.wrap_socket(raw, server_hostname=host)


def _split_cmd(line: str) -> Tuple[str, List[str]]:
    line = line.strip()
    if not line:
        return "", []
    # Preserve original "print filename" UX
    parts = line.split()
    cmd = parts[0].upper()
    args = parts[1:]
    if cmd == "PRINT" and len(args) >= 1:
        # allow: print filename with spaces? (not supported for safety)
        args = [args[0]]
    return cmd, args


def _pretty_print_response(resp: dict) -> None:
    if resp.get("ok") is True:
        msg = resp.get("msg")
        if msg:
            print(msg)

        data = resp.get("data")
        if isinstance(data, dict) and "commands" in data:
            for c in data["commands"]:
                print(" -", c)
        elif data is not None:
            # Pretty-print other payloads (e.g., STATUS / WHOAMI)
            try:
                import json as _json
                print(_json.dumps(data, indent=2, ensure_ascii=False))
            except Exception:
                print(data)
        return

    code = resp.get("code", "ERROR")
    msg = resp.get("msg", "")
    print(f"[{code}] {msg}")



def main() -> None:
    ap = argparse.ArgumentParser(description="NetRepo Secure Client")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--tls", action="store_true", help="Use TLS (recommended)")
    ap.add_argument("--cafile", default=CERT_DEFAULT, help="CA/cert file to trust (self-signed pin)")
    ap.add_argument("--downloads", default=DOWNLOADS_DIR_DEFAULT)
    args = ap.parse_args()

    os.makedirs(args.downloads, exist_ok=True)

    try:
        sock = _make_socket(args.host, args.port, args.tls, args.cafile)
    except Exception as e:
        print("Failed to connect:", e)
        return

    try:
        banner = recv_json(sock)
        _pretty_print_response(banner)
    except Exception as e:
        print("Failed to read server banner:", e)
        sock.close()
        return

    print("\nType HELP to see commands. Ctrl+C or QUIT to exit.\n")

    while True:
        try:
            line = input("netrepo> ")
        except (EOFError, KeyboardInterrupt):
            line = "QUIT"

        cmd, args_list = _split_cmd(line)
        if not cmd:
            continue

        # Friendly aliases
        if cmd.lower() == "list":
            cmd = "LIST"

        if cmd in ("GET", "PRINT"):
            if len(args_list) != 1:
                print("Usage:", cmd, "<filename>")
                continue
            send_json(sock, {"cmd": cmd, "args": args_list})
            try:
                resp = recv_json(sock)
            except (ProtocolError, socket.timeout, OSError) as e:
                print("Connection error:", e)
                break

            if not resp.get("ok"):
                _pretty_print_response(resp)
                continue

            data = resp.get("data", {})
            filename = data.get("filename", "download.bin")
            b64 = data.get("b64", "")
            expected = data.get("sha256", "")

            try:
                file_bytes = base64.b64decode(b64.encode("ascii"), validate=True)
            except Exception:
                print("[CLIENT_ERROR] Invalid base64 payload received")
                continue

            got = sha256_bytes(file_bytes)
            if expected and got != expected:
                print("[INTEGRITY_FAIL] SHA-256 mismatch; refusing to use file")
                continue

            # If PRINT and utf-8, display; otherwise save
            if cmd == "PRINT":
                try:
                    text = file_bytes.decode("utf-8")
                    print(text.rstrip("\n"))
                    continue
                except UnicodeDecodeError:
                    pass

            out_path = os.path.join(args.downloads, filename)
            with open(out_path, "wb") as f:
                f.write(file_bytes)
            print(f"Saved to {out_path} ({len(file_bytes)} bytes, sha256={got[:12]}...)")
            continue

        # Normal command
        send_json(sock, {"cmd": cmd, "args": args_list})
        try:
            resp = recv_json(sock)
        except (ProtocolError, socket.timeout, OSError) as e:
            print("Connection error:", e)
            break

        if cmd == "LIST" and resp.get("ok"):
            files = (resp.get("data") or {}).get("files", [])
            if files:
                for f in files:
                    print("-", f)
            else:
                print("(no files)")
            continue

        if cmd in ("QUIT",):
            _pretty_print_response(resp)
            break

        _pretty_print_response(resp)

    try:
        sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
