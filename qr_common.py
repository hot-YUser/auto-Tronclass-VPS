#!/usr/bin/env python3
"""Shared validation helpers for the QR keeper and read-only API."""
from __future__ import annotations

import datetime
import json
import math
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from typing import Mapping, Optional


TOKEN_RE = re.compile(r"[0-9]{10}[0-9a-f]{32}\Z")
KEY_ID_RE = re.compile(r"k_[0-9a-f]{8}\Z")
KEY_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_KEY_LABEL_LENGTH = 128
_PLACEHOLDER_MARKERS = (
    "changeme",
    "change-me",
    "placeholder",
    "replace-with",
    "replace_me",
    "your-secret",
    "your_secret",
)


class ConfigError(ValueError):
    """Raised when startup configuration is missing or unsafe."""


def _raw(env: Mapping[str, str], name: str, default: Optional[str]) -> str:
    value = env.get(name, default)
    if value is None:
        return ""
    return str(value).strip()


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return ("<" in value or ">" in value
            or any(marker in lowered for marker in _PLACEHOLDER_MARKERS))


def env_text(env: Mapping[str, str], name: str, default: Optional[str] = None,
             required: bool = False, allow_placeholder: bool = False) -> str:
    """Return a trimmed environment value without ever echoing it in errors."""
    value = _raw(env, name, default)
    if required and not value:
        raise ConfigError("{} must not be empty".format(name))
    if value and not allow_placeholder and _is_placeholder(value):
        raise ConfigError("{} contains a placeholder".format(name))
    return value


def env_int(env: Mapping[str, str], name: str, default: int,
            minimum: Optional[int] = None, maximum: Optional[int] = None) -> int:
    raw = _raw(env, name, str(default))
    if not raw:
        raise ConfigError("{} must not be empty".format(name))
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        raise ConfigError("{} must be an integer".format(name))
    if minimum is not None and value < minimum:
        raise ConfigError("{} is below its minimum".format(name))
    if maximum is not None and value > maximum:
        raise ConfigError("{} is above its maximum".format(name))
    return value


def env_float(env: Mapping[str, str], name: str, default: float,
              minimum: Optional[float] = None, maximum: Optional[float] = None,
              minimum_exclusive: bool = False) -> float:
    raw = _raw(env, name, str(default))
    if not raw:
        raise ConfigError("{} must not be empty".format(name))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ConfigError("{} must be a number".format(name))
    if not math.isfinite(value):
        raise ConfigError("{} must be finite".format(name))
    if minimum is not None:
        if minimum_exclusive and value <= minimum:
            raise ConfigError("{} must be greater than its minimum".format(name))
        if not minimum_exclusive and value < minimum:
            raise ConfigError("{} is below its minimum".format(name))
    if maximum is not None and value > maximum:
        raise ConfigError("{} is above its maximum".format(name))
    return value


def env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = _raw(env, name, "true" if default else "false").lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError("{} must be true or false".format(name))


def env_choice(env: Mapping[str, str], name: str, default: str, choices) -> str:
    value = env_text(env, name, default=default, required=True).lower()
    if value not in choices:
        raise ConfigError("{} has an invalid mode".format(name))
    return value


def env_utc_date(env: Mapping[str, str], name: str,
                 required: bool = False) -> str:
    value = env_text(env, name, required=required)
    if not value:
        return ""
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ConfigError("{} must use YYYY-MM-DD".format(name))
    if parsed.strftime("%Y-%m-%d") != value:
        raise ConfigError("{} must use YYYY-MM-DD".format(name))
    return value


def _fsync_directory(path: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _replace_with_retry(source: str, target: str) -> None:
    for attempt in range(20):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.01)


def write_json_atomic(path, obj, *, durable: bool = False, **dump_options) -> None:
    """Atomically replace JSON using a unique same-directory 0600 temp file.

    `durable=True` additionally fsyncs the file and parent directory for key/control metadata.
    High-frequency token/state writers use atomic visibility without forcing storage every poll.
    """
    target = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(target) or "."
    if os.path.lexists(target) and stat.S_ISLNK(os.lstat(target).st_mode):
        raise OSError("refusing to replace a symlink")
    descriptor, tmp = tempfile.mkstemp(
        prefix=".{}-".format(os.path.basename(target)),
        suffix=".tmp",
        dir=parent,
        text=True,
    )
    try:
        try:
            os.fchmod(descriptor, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(obj, handle, **dump_options)
            handle.flush()
            if durable:
                os.fsync(handle.fileno())
        _replace_with_retry(tmp, target)
        if durable:
            _fsync_directory(parent)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def validate_api_key_store(data):
    """Return a validated current-schema key list; any corrupt record invalidates the store."""
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, list):
        raise ValueError("invalid API key store")
    ids = set()
    hashes = set()
    for record in keys:
        if not isinstance(record, dict):
            raise ValueError("invalid API key store")
        kid = record.get("id")
        digest = record.get("hash")
        label = record.get("label", "")
        expiry = record.get("expires_epoch")
        if not isinstance(kid, str) or KEY_ID_RE.fullmatch(kid) is None:
            raise ValueError("invalid API key store")
        if not isinstance(digest, str) or KEY_HASH_RE.fullmatch(digest) is None:
            raise ValueError("invalid API key store")
        if kid in ids or digest in hashes:
            raise ValueError("duplicate API key record")
        if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry <= 0:
            raise ValueError("invalid API key store")
        if not isinstance(record.get("revoked"), bool):
            raise ValueError("invalid API key store")
        if not isinstance(label, str) or len(label) > MAX_KEY_LABEL_LENGTH \
                or any(ord(char) < 32 or ord(char) == 127 for char in label):
            raise ValueError("invalid API key store")
        for field in ("created_utc", "expires_utc"):
            if not isinstance(record.get(field), str) or not record[field]:
                raise ValueError("invalid API key store")
        ids.add(kid)
        hashes.add(digest)
    return keys


@dataclass(frozen=True)
class TokenValidation:
    error: str
    age_ms: Optional[int]
    timestamp: Optional[int]

    @property
    def valid(self) -> bool:
        return not self.error


def validate_token_record(record, now_ms: int, stale_ms: int,
                          future_skew_ms: int) -> TokenValidation:
    """Strictly validate token shape, timestamp consistency, age, and skew."""
    if stale_ms < 0 or future_skew_ms < 0:
        raise ValueError("token age bounds must be non-negative")
    if not isinstance(record, dict) or record.get("ok") is not True:
        return TokenValidation("invalid", None, None)
    data = record.get("data")
    if not isinstance(data, str) or TOKEN_RE.fullmatch(data) is None:
        return TokenValidation("shape", None, None)
    timestamp = record.get("ts")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        return TokenValidation("timestamp", None, None)
    embedded = int(data[:10])
    if embedded != timestamp:
        return TokenValidation("timestamp_mismatch", None, timestamp)
    age_ms = int(now_ms) - timestamp * 1000
    if age_ms > stale_ms:
        return TokenValidation("stale", age_ms, timestamp)
    if age_ms < -future_skew_ms:
        return TokenValidation("future", age_ms, timestamp)
    return TokenValidation("", age_ms, timestamp)
