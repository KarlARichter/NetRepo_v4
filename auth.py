"""
NetRepo Secure - Authentication & authorization

Stores users in a local JSON file:
{
  "users": {
     "alice": {"bcrypt_hash":"...", "role":"user"},
     "admin": {"bcrypt_hash":"...", "role":"admin"}
  }
}
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Optional

import bcrypt


DEFAULT_USERS = {
    "admin": {"password": "admin123!", "role": "admin"},
    "user": {"password": "user123!", "role": "user"},
}


@dataclass(frozen=True)
class User:
    username: str
    role: str


def _hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def _verify_password(password: str, bcrypt_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), bcrypt_hash.encode("utf-8"))
    except Exception:
        return False


def init_user_db(path: str) -> None:
    """Create users.json if missing, with a demo admin and user."""
    if os.path.exists(path):
        return
    users = {}
    for uname, info in DEFAULT_USERS.items():
        users[uname] = {"bcrypt_hash": _hash_password(info["password"]), "role": info["role"]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"users": users}, f, indent=2)


def load_user_db(path: str) -> Dict[str, Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    users = data.get("users", {})
    if not isinstance(users, dict):
        raise ValueError("Invalid users database format")
    return users


def save_user_db(path: str, users: Dict[str, Dict[str, str]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"users": users}, f, indent=2)


def authenticate(path: str, username: str, password: str) -> Optional[User]:
    users = load_user_db(path)
    rec = users.get(username)
    if not rec:
        return None
    if _verify_password(password, rec.get("bcrypt_hash", "")):
        return User(username=username, role=rec.get("role", "user"))
    return None


def require_role(user: Optional[User], needed: str) -> bool:
    if user is None:
        return False
    if needed == "user":
        return user.role in ("user", "admin")
    if needed == "admin":
        return user.role == "admin"
    return False


def add_user(path: str, username: str, password: str, role: str = "user") -> None:
    role = role.lower()
    if role not in ("user", "admin"):
        raise ValueError("role must be 'user' or 'admin'")
    users = load_user_db(path)
    if username in users:
        raise ValueError("user already exists")
    users[username] = {"bcrypt_hash": _hash_password(password), "role": role}
    save_user_db(path, users)


def change_password(path: str, username: str, new_password: str) -> None:
    users = load_user_db(path)
    if username not in users:
        raise ValueError("user not found")
    users[username]["bcrypt_hash"] = _hash_password(new_password)
    save_user_db(path, users)
