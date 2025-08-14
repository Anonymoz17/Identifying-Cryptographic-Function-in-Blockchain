# auth.py
from dataclasses import dataclass, asdict
import hashlib
from typing import Dict, Optional, Tuple

def _hash_pw(pw: str) -> str:
    # NOTE: demo only; replace with bcrypt/argon2 in production.
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

@dataclass
class User:
    full_name: str
    email: str
    username: str
    password_hash: str

class UserStore:
    def __init__(self):
        self._users: Dict[str, User] = {}
        self.current_username: Optional[str] = None

    # --- session helpers ---
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        u = self._users.get(username)
        if not u:
            return False, "User not found."
        if u.password_hash != _hash_pw(password):
            return False, "Incorrect password."
        self.current_username = username
        return True, "Logged in."

    def logout(self):
        self.current_username = None

    def current_user(self) -> Optional[User]:
        if not self.current_username:
            return None
        return self._users.get(self.current_username)

    # --- user CRUD ---
    def create_user(self, full_name: str, email: str, username: str, password: str) -> Tuple[bool, str]:
        if username in self._users:
            return False, "Username is already taken."
        self._users[username] = User(
            full_name=full_name,
            email=email,
            username=username,
            password_hash=_hash_pw(password),
        )
        return True, "Account created."

    def update_user(self, username: str, *, full_name: Optional[str]=None,
                    email: Optional[str]=None, password: Optional[str]=None) -> Tuple[bool, str]:
        u = self._users.get(username)
        if not u:
            return False, "User not found."
        if full_name is not None:
            u.full_name = full_name
        if email is not None:
            u.email = email
        if password is not None:
            u.password_hash = _hash_pw(password)
        return True, "Account updated."

    def delete_user(self, username: str) -> Tuple[bool, str]:
        if username not in self._users:
            return False, "User not found."
        del self._users[username]
        if self.current_username == username:
            self.current_username = None
        return True, "Account deleted."

# Singleton-ish store for the app
store = UserStore()
