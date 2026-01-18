"""
NetRepo Secure - Server
A secure, multithreaded TCP/TLS file repository service.

Features implemented:
- Length-prefixed JSON protocol (binary-safe framing)
- Authentication (bcrypt) + RBAC
- TLS (ssl) for data-in-transit protection
- Directory traversal protection + filename validation
- SHA-256 integrity hashes for downloads
- Rate limiting (token bucket) to reduce abuse/DoS risk
- Rotating audit logs

Default credentials (demo only):
- admin / admin123!
- user  / user123!
Change these by using ADMIN commands or editing users.json.
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import threading
import time
from typing import Dict, Optional, Tuple

from protocol import send_json, recv_json, ProtocolError
from auth import init_user_db, authenticate, require_role, add_user, change_password, User
from security import safe_join, sha256_bytes, TokenBucket
from logutil import setup_logger


REPO_DIR_DEFAULT = os.path.join(os.path.dirname(__file__), "repo")
USERS_DB_DEFAULT = os.path.join(os.path.dirname(__file__), "users.json")
CERT_DEFAULT = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
KEY_DEFAULT = os.path.join(os.path.dirname(__file__), "certs", "server.key")
LOG_DIR_DEFAULT = os.path.join(os.path.dirname(__file__), "logs")

MAX_CLIENTS_DEFAULT = 10
SOCKET_TIMEOUT_SEC = 600  # seconds (10 minutes)
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5MB safety cap for base64-in-JSON transfers


class ClientState:
    def __init__(self, addr: Tuple[str, int]) -> None:
        self.addr = addr
        self.user: Optional[User] = None
        self.bucket = TokenBucket()
        self.connected_at = time.time()


class NetRepoServer:
    def __init__(
        self,
        host: str,
        port: int,
        repo_dir: str,
        users_db: str,
        cert_path: str,
        key_path: str,
        max_clients: int,
        use_tls: bool,
        log_dir: str,
    ) -> None:
        self.host = host
        self.port = port
        self.repo_dir = os.path.abspath(repo_dir)
        self.users_db = users_db
        self.cert_path = cert_path
        self.key_path = key_path
        self.max_clients = max_clients
        self.use_tls = use_tls

        self.logger = setup_logger("netrepo", log_dir)

        self._clients_lock = threading.Lock()
        self._clients: Dict[socket.socket, ClientState] = {}

        self._start_time = time.time()

        os.makedirs(self.repo_dir, exist_ok=True)
        init_user_db(self.users_db)

    def _wrap_tls(self, conn: socket.socket) -> socket.socket:
        if not self.use_tls:
            return conn
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if not (os.path.exists(self.cert_path) and os.path.exists(self.key_path)):
            raise FileNotFoundError(
                f"TLS enabled but cert/key not found. Run scripts/generate_certs.* to create {self.cert_path} and {self.key_path}"
            )
        ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        # Disable legacy protocols (best-effort)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx.wrap_socket(conn, server_side=True)

    def _client_count(self) -> int:
        with self._clients_lock:
            return len(self._clients)

    def _register_client(self, conn: socket.socket, state: ClientState) -> bool:
        with self._clients_lock:
            if len(self._clients) >= self.max_clients:
                return False
            self._clients[conn] = state
            return True

    def _unregister_client(self, conn: socket.socket) -> None:
        with self._clients_lock:
            self._clients.pop(conn, None)

    def _send_error(self, conn: socket.socket, code: str, msg: str) -> None:
        send_json(conn, {"ok": False, "code": code, "msg": msg})

    def _send_ok(self, conn: socket.socket, msg: str = "", data=None) -> None:
        payload = {"ok": True}
        if msg:
            payload["msg"] = msg
        if data is not None:
            payload["data"] = data
        send_json(conn, payload)

    def _cmd_help(self, conn: socket.socket, state: ClientState) -> None:
        cmds = [
            "HELP",
            "LOGIN <username> <password>",
            "LOGOUT",
            "WHOAMI",
            "LIST",
            "GET <filename>   (alias: PRINT <filename>)",
            "STATUS           (admin only)",
            "ADDUSER <username> <password> <role:user|admin>  (admin only)",
            "CHPASS <username> <new_password>                 (admin only)",
            "QUIT",
        ]
        self._send_ok(conn, data={"commands": cmds})

    def _cmd_login(self, conn: socket.socket, state: ClientState, args) -> None:
        if len(args) != 2:
            self._send_error(conn, "BAD_REQUEST", "Usage: LOGIN <username> <password>")
            return
        username, password = args
        user = authenticate(self.users_db, username, password)
        if not user:
            self.logger.info("AUTH_FAIL addr=%s user=%s", state.addr, username)
            self._send_error(conn, "AUTH_FAILED", "Invalid username or password")
            return
        state.user = user
        self.logger.info("AUTH_OK addr=%s user=%s role=%s", state.addr, user.username, user.role)
        self._send_ok(conn, msg=f"Logged in as {user.username} ({user.role})")

    def _cmd_logout(self, conn: socket.socket, state: ClientState) -> None:
        if state.user:
            self.logger.info("LOGOUT addr=%s user=%s", state.addr, state.user.username)
        state.user = None
        self._send_ok(conn, msg="Logged out")

    def _cmd_whoami(self, conn: socket.socket, state: ClientState) -> None:
        if not state.user:
            self._send_ok(conn, data={"authenticated": False})
            return
        self._send_ok(conn, data={"authenticated": True, "username": state.user.username, "role": state.user.role})

    def _cmd_list(self, conn: socket.socket, state: ClientState) -> None:
        if not require_role(state.user, "user"):
            self._send_error(conn, "UNAUTHORIZED", "LOGIN required")
            return
        files = []
        try:
            for name in sorted(os.listdir(self.repo_dir)):
                full = os.path.join(self.repo_dir, name)
                if os.path.isfile(full):
                    files.append(name)
        except Exception as e:
            self._send_error(conn, "SERVER_ERROR", f"Failed to list repo: {e}")
            return
        self.logger.info("LIST addr=%s user=%s count=%d", state.addr, state.user.username, len(files))
        self._send_ok(conn, data={"files": files})

    def _cmd_get(self, conn: socket.socket, state: ClientState, args) -> None:
        if not require_role(state.user, "user"):
            self._send_error(conn, "UNAUTHORIZED", "LOGIN required")
            return
        if len(args) != 1:
            self._send_error(conn, "BAD_REQUEST", "Usage: GET <filename>")
            return
        filename = args[0]
        fpath = safe_join(self.repo_dir, filename)
        if not fpath or not os.path.isfile(fpath):
            self.logger.info("GET_NOTFOUND addr=%s user=%s file=%s", state.addr, state.user.username, filename)
            self._send_error(conn, "NOT_FOUND", "File not found")
            return

        try:
            size = os.path.getsize(fpath)
            if size > MAX_FILE_BYTES:
                self._send_error(conn, "TOO_LARGE", f"File too large for JSON transfer ({size} bytes)")
                return
            with open(fpath, "rb") as f:
                data = f.read()
        except Exception as e:
            self._send_error(conn, "SERVER_ERROR", f"Failed to read file: {e}")
            return

        digest = sha256_bytes(data)
        b64 = __import__("base64").b64encode(data).decode("ascii")
        self.logger.info("GET_OK addr=%s user=%s file=%s bytes=%d", state.addr, state.user.username, filename, len(data))
        self._send_ok(conn, data={"filename": filename, "sha256": digest, "b64": b64, "bytes": len(data)})

    def _cmd_status(self, conn: socket.socket, state: ClientState) -> None:
        if not require_role(state.user, "admin"):
            self._send_error(conn, "FORBIDDEN", "Admin role required")
            return
        uptime = int(time.time() - self._start_time)
        self._send_ok(
            conn,
            data={
                "clients": self._client_count(),
                "max_clients": self.max_clients,
                "uptime_sec": uptime,
                "repo_dir": self.repo_dir,
                "tls": self.use_tls,
            },
        )

    def _cmd_adduser(self, conn: socket.socket, state: ClientState, args) -> None:
        if not require_role(state.user, "admin"):
            self._send_error(conn, "FORBIDDEN", "Admin role required")
            return
        if len(args) != 3:
            self._send_error(conn, "BAD_REQUEST", "Usage: ADDUSER <username> <password> <role:user|admin>")
            return
        uname, pwd, role = args
        try:
            add_user(self.users_db, uname, pwd, role)
        except Exception as e:
            self._send_error(conn, "BAD_REQUEST", str(e))
            return
        self.logger.info("ADDUSER addr=%s admin=%s new_user=%s role=%s", state.addr, state.user.username, uname, role)
        self._send_ok(conn, msg=f"Created user {uname} with role {role}")

    def _cmd_chpass(self, conn: socket.socket, state: ClientState, args) -> None:
        if not require_role(state.user, "admin"):
            self._send_error(conn, "FORBIDDEN", "Admin role required")
            return
        if len(args) != 2:
            self._send_error(conn, "BAD_REQUEST", "Usage: CHPASS <username> <new_password>")
            return
        uname, pwd = args
        try:
            change_password(self.users_db, uname, pwd)
        except Exception as e:
            self._send_error(conn, "BAD_REQUEST", str(e))
            return
        self.logger.info("CHPASS addr=%s admin=%s target=%s", state.addr, state.user.username, uname)
        self._send_ok(conn, msg=f"Updated password for {uname}")

    def _dispatch(self, conn: socket.socket, state: ClientState, msg: dict) -> bool:
        """
        Returns False if connection should close.
        """
        cmd = str(msg.get("cmd", "")).upper().strip()
        args = msg.get("args", [])
        if not isinstance(args, list):
            args = []

        # Rate limit: deny before heavy work
        if not state.bucket.allow(1.0):
            self.logger.info("RATELIMIT addr=%s user=%s", state.addr, getattr(state.user, "username", None))
            self._send_error(conn, "RATE_LIMIT", "Too many requests; slow down")
            return True

        if cmd in ("HELP", "?"):
            self._cmd_help(conn, state)
        elif cmd == "LOGIN":
            self._cmd_login(conn, state, args)
        elif cmd == "LOGOUT":
            self._cmd_logout(conn, state)
        elif cmd == "WHOAMI":
            self._cmd_whoami(conn, state)
        elif cmd == "LIST":
            self._cmd_list(conn, state)
        elif cmd in ("GET", "PRINT"):
            self._cmd_get(conn, state, args)
        elif cmd == "STATUS":
            self._cmd_status(conn, state)
        elif cmd == "ADDUSER":
            self._cmd_adduser(conn, state, args)
        elif cmd == "CHPASS":
            self._cmd_chpass(conn, state, args)
        elif cmd == "QUIT":
            self._send_ok(conn, msg="EXIT")
            return False
        else:
            self._send_error(conn, "UNKNOWN_CMD", f"Unknown command: {cmd}. Try HELP.")
        return True

    def _handle_client(self, raw_conn: socket.socket, addr: Tuple[str, int]) -> None:
        conn = raw_conn
        try:
            conn = self._wrap_tls(raw_conn)
            conn.settimeout(SOCKET_TIMEOUT_SEC)
            state = ClientState(addr)
            if not self._register_client(conn, state):
                # best-effort plain send; if TLS, conn is wrapped already
                try:
                    send_json(conn, {"ok": False, "code": "CAPACITY", "msg": "Server at full capacity"})
                except Exception:
                    pass
                conn.close()
                return

            self.logger.info("CONNECT addr=%s tls=%s", addr, self.use_tls)
            send_json(conn, {"ok": True, "msg": "Welcome to NetRepo Secure."})

            while True:
                try:
                    msg = recv_json(conn)
                except (socket.timeout, ProtocolError) as e:
                    self.logger.info("DISCONNECT addr=%s reason=%s", addr, str(e))
                    break
                except Exception as e:
                    self.logger.info("DISCONNECT addr=%s reason=%s", addr, str(e))
                    break

                try:
                    keep = self._dispatch(conn, state, msg)
                except Exception as e:
                    self.logger.exception("DISPATCH_ERROR addr=%s err=%s", addr, str(e))
                    self._send_error(conn, "SERVER_ERROR", "Internal server error")
                    keep = True
                if not keep:
                    break
        except ssl.SSLError as e:
            self.logger.info("TLS_ERROR addr=%s err=%s", addr, str(e))
        except Exception as e:
            self.logger.info("CLIENT_ERROR addr=%s err=%s", addr, str(e))
        finally:
            try:
                self._unregister_client(conn)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def serve_forever(self) -> None:
        self.logger.info("Starting NetRepo Secure server on %s:%d tls=%s", self.host, self.port, self.use_tls)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            while True:
                conn, addr = s.accept()
                # Use a raw socket first; TLS wrap happens in the handler thread
                t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                t.start()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NetRepo Secure Server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9999)
    p.add_argument("--repo", default=REPO_DIR_DEFAULT)
    p.add_argument("--users", default=USERS_DB_DEFAULT)
    p.add_argument("--max-clients", type=int, default=MAX_CLIENTS_DEFAULT)
    p.add_argument("--tls", action="store_true", help="Enable TLS (recommended)")
    p.add_argument("--cert", default=CERT_DEFAULT)
    p.add_argument("--key", default=KEY_DEFAULT)
    p.add_argument("--logs", default=LOG_DIR_DEFAULT)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    server = NetRepoServer(
        host=args.host,
        port=args.port,
        repo_dir=args.repo,
        users_db=args.users,
        cert_path=args.cert,
        key_path=args.key,
        max_clients=args.max_clients,
        use_tls=args.tls,
        log_dir=args.logs,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
