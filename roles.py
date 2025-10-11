# roles.py
from typing import Literal
Role = Literal["free", "premium", "admin"]

def is_admin(role: str | None) -> bool:   return role == "admin"
def is_premium(role: str | None) -> bool: return role in ("premium", "admin")
def is_free(role: str | None) -> bool:    return role == "free"
