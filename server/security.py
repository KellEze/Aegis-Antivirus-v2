"""Utilitários de segurança: CSRF, limite de tentativas e validações."""
from __future__ import annotations

import hmac
import re
import secrets
import threading
import time
from datetime import datetime
from typing import Optional

from flask import abort, request, session

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


# ---------------------------------------------------------------- CSRF
def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def verify_csrf() -> None:
    sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400)


# ---------------------------------------------------------------- Limite de tentativas
class RateLimiter:
    """Bloqueia uma chave (ex.: IP + e-mail) após muitas falhas seguidas."""

    def __init__(self, max_failures: int = 5, window: int = 600, block: int = 300):
        self.max_failures = max_failures
        self.window = window
        self.block = block
        self._failures: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> bool:
        with self._lock:
            until = self._blocked_until.get(key, 0)
            if until > time.time():
                return True
            self._blocked_until.pop(key, None)
            return False

    def fail(self, key: str) -> None:
        now = time.time()
        with self._lock:
            recent = [t for t in self._failures.get(key, []) if now - t < self.window]
            recent.append(now)
            self._failures[key] = recent
            if len(recent) >= self.max_failures:
                self._blocked_until[key] = now + self.block
                self._failures.pop(key, None)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)


# ---------------------------------------------------------------- Validações
def valid_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email)) and len(email) <= 254


def password_problem(password: str) -> Optional[str]:
    if len(password) < 8:
        return "A senha deve ter pelo menos 8 caracteres."
    if len(password) > 128:
        return "A senha pode ter no máximo 128 caracteres."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "A senha deve conter letras e números."
    return None


def safe_next(url: Optional[str]) -> Optional[str]:
    """Aceita somente caminhos internos (evita redirecionamento para sites externos)."""
    if url and url.startswith("/") and not url.startswith("//") and "\\" not in url:
        return url
    return None


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def card_brand(number: str) -> str:
    n = re.sub(r"\D", "", number)
    if n.startswith("4"):
        return "Visa"
    if re.match(r"^(5[1-5]|2[2-7])", n):
        return "Mastercard"
    if re.match(r"^3[47]", n):
        return "Amex"
    if re.match(r"^(636368|438935|504175|451416|636297|5067|4576|4011|506699)", n):
        return "Elo"
    return "Cartão"


def card_expiry_valid(value: str) -> bool:
    m = re.fullmatch(r"(\d{2})\s*/\s*(\d{2})", value.strip())
    if not m:
        return False
    month, year = int(m.group(1)), 2000 + int(m.group(2))
    if not 1 <= month <= 12:
        return False
    now = datetime.now()
    return (year, month) >= (now.year, now.month)
