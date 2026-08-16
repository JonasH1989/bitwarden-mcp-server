"""
Vaultwarden HTTP-based MCP Server Client.

This module provides a client for interacting with Vaultwarden via direct
HTTP requests (no bw CLI dependency). Uses OAuth2 client_credentials flow
for authentication.

Why HTTP instead of bw CLI?
- bw 2026.2.0 with --apikey was opaque about Vaultwarden's actual responses
- Direct HTTP gives us full visibility into every JSON/HTML response
- Smaller container image (no Node.js + bw CLI needed)
"""

import base64
import hashlib
import json
import logging
import os
import urllib.parse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF

# Suppress SSL warnings (we deliberately skip cert verification because
# Vaultwarden uses self-signed certs in Jonas' deployment)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BitwardenItem:
    """Represents a Vaultwarden item (password, note, etc.)"""
    id: str
    name: str
    username: Optional[str] = None
    password: Optional[str] = None
    uris: List[str] = None
    notes: Optional[str] = None
    folder_id: Optional[str] = None
    type: int = 1  # 1=Login, 2=SecureNote, 3=Card, 4=Identity
    favorite: bool = False

    def __post_init__(self):
        if self.uris is None:
            self.uris = []


# Default configuration (env-driven)
DEFAULT_BASE_URL = os.getenv("BITWARDEN_BASE_URL", "https://vault.bitwarden.com")
DEFAULT_API_KEY = os.getenv("BITWARDEN_CLIENT_ID", "")  # OAuth2 client_id (user.xxx UUID)
DEFAULT_CLIENT_SECRET = os.getenv("BITWARDEN_CLIENT_SECRET", "")
# Legacy fields (deprecated)
DEFAULT_EMAIL = os.getenv("BITWARDEN_EMAIL", "")
DEFAULT_PASSWORD = os.getenv("BITWARDEN_PASSWORD", "")


class BitwardenCLIClient:
    """HTTP-based client for Vaultwarden.

    Uses OAuth2 client_credentials flow for authentication.
    Subsequent API calls use Authorization: Bearer <access_token>.
    """

    # Vaultwarden/Bitwarden item type mapping
    TYPE_MAP = {"login": 1, "note": 2, "card": 3, "identity": 4}

    def __init__(self, base_url: str, api_key: Optional[str] = None,
                 email: Optional[str] = None, password: Optional[str] = None,
                 client_secret: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.email = email
        self.password = password
        self.client_secret = client_secret

        # OAuth2 tokens
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[float] = None

        # Device identification (Vaultwarden requires this for OAuth2)
        self.device_identifier = "ustack-bitwarden-mcp-server"
        self.device_name = "Ustack Bitwarden MCP Server"
        self.device_type = "8"  # 8 = Server / CLI per Bitwarden device types

        # HTTP session (reuses connection pool)
        self.session = requests.Session()
        self.session.verify = False  # Skip TLS cert verification (self-signed Vaultwarden)
        self.session.headers.update({
            "User-Agent": "ustack-bitwarden-mcp/2.0.0",
            "Accept": "application/json",
        })

        # Encryption state (derived after OAuth2)
        self.user_key: Optional[bytes] = None  # Symmetric key for decrypting cipher fields
        self.user_email: Optional[str] = None  # Cached from /api/sync profile

    # ----- OAuth2 Authentication -----

    def authenticate(self) -> bool:
        """OAuth2 client_credentials flow via /identity/connect/token.

        Returns True on success (access_token set), False otherwise.
        """
        if not self.api_key or not self.client_secret:
            logger.error(
                "Missing API key or client secret. "
                "Set BITWARDEN_CLIENT_ID and BITWARDEN_CLIENT_SECRET."
            )
            return False

        token_url = f"{self.base_url}/identity/connect/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.api_key,
            "client_secret": self.client_secret,
            "scope": "api",
            "device_identifier": self.device_identifier,
            "device_name": self.device_name,
            "device_type": self.device_type,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        logger.info(f"OAuth2 token request to {token_url}")
        try:
            resp = self.session.post(
                token_url, data=payload, headers=headers, timeout=30
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"OAuth2 HTTP error: {e}")
            return False

        logger.info(f"OAuth2 response: HTTP {resp.status_code}")
        # Log response body (truncated) for debugging
        body_preview = resp.text[:500] if resp.text else ""
        logger.info(f"OAuth2 response body (first 500 chars): {body_preview!r}")

        if resp.status_code != 200:
            logger.error(
                f"OAuth2 token request failed with status {resp.status_code}"
            )
            return False

        try:
            token_data = resp.json()
        except json.JSONDecodeError:
            logger.error(f"OAuth2 response is not JSON: {resp.text[:200]!r}")
            return False

        self.access_token = token_data.get("access_token")
        self.refresh_token = token_data.get("refresh_token")
        # expires_in is in seconds
        if "expires_in" in token_data:
            import time
            self.token_expires_at = time.time() + token_data["expires_in"]

        if not self.access_token:
            logger.error(
                f"No access_token in OAuth2 response: {token_data!r}"
            )
            return False

        logger.info("OAuth2 authentication successful — access_token set")

        # === Step 2: Derive user encryption key from master password ===
        # Get KDF iterations via /identity/accounts/prelogin
        email_from_token = token_data.get("email", "")
        try:
            prelogin_resp = self.session.post(
                f"{self.base_url}/identity/accounts/prelogin",
                json={"email": email_from_token},
                timeout=10
            )
            # Diagnostic: log FULL prelogin response (kdf type, kdfIterations, kdfMemory, kdfParallelism)
            try:
                prelogin_data = prelogin_resp.json()
                logger.info(
                    f"prelogin response: {prelogin_data}"
                )
            except Exception:
                prelogin_data = {}
            if prelogin_resp.status_code == 200:
                kdf = prelogin_data.get("kdf", 0)
                kdf_iterations = prelogin_data.get("kdfIterations", 600000)
                kdf_memory = prelogin_data.get("kdfMemory")
                kdf_parallelism = prelogin_data.get("kdfParallelism")
                logger.info(
                    f"prelogin: kdf={kdf} kdfIterations={kdf_iterations} "
                    f"kdfMemory={kdf_memory} kdfParallelism={kdf_parallelism}"
                )
                if kdf != 0:
                    logger.error(
                        f"Unsupported KDF type: {kdf} (only 0=PBKDF2 supported). "
                        f"User might use Argon2id (kdf=1) or another algorithm."
                    )
            else:
                logger.warning(f"prelogin failed ({prelogin_resp.status_code}), using default 600000")
                kdf_iterations = 600000
        except Exception as e:
            logger.warning(f"prelogin error: {e}, using default 600000")
            kdf_iterations = 600000

        # Get email + encrypted user key from /api/sync
        try:
            sync_resp = self._request("GET", "/api/sync", timeout=30)
            if sync_resp.status_code == 200:
                sync_data = sync_resp.json()
                profile = sync_data.get("profile", {})
                email = profile.get("email", email_from_token)
                self.user_email = email
                master_pw_unlock = (
                    sync_data.get("userDecryption", {}).get("masterPasswordUnlock")
                )
                if master_pw_unlock and email:
                    master_password = os.getenv("BITWARDEN_PASSWORD", "")
                    if master_password:
                        try:
                            mk_v2, mk_v1 = self._derive_master_keys(
                                master_password, email, kdf_iterations
                            )
                            # Try v2 first (current Bitwarden standard)
                            self.user_key = self._decrypt_user_key(
                                master_pw_unlock, mk_v2
                            )
                            auth_method_used = "v2"
                            if self.user_key is None:
                                # Try v1 (legacy, for older accounts)
                                logger.info("v2 decryption failed, trying v1...")
                                self.user_key = self._decrypt_user_key(
                                    master_pw_unlock, mk_v1
                                )
                                auth_method_used = "v1"
                            if self.user_key:
                                logger.info(
                                    f"User key derived and decrypted successfully "
                                    f"(auth method: {auth_method_used}, "
                                    f"email={email}, kdf_iter={kdf_iterations})"
                                )
                            else:
                                logger.error(
                                    "Failed to decrypt user key (both v2 and v1 failed)"
                                )
                        except Exception as e:
                            logger.error(f"Key derivation error: {e}")
                    else:
                        logger.warning(
                            "BITWARDEN_PASSWORD env var not set — "
                            "ciphers cannot be decrypted"
                        )
        except Exception as e:
            logger.warning(f"/api/sync for key derivation failed: {e}")

        return True

    def logout(self) -> bool:
        """Clear tokens (no explicit logout endpoint needed for client_credentials)."""
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        logger.info("Logged out (tokens cleared)")
        return True

    def _ensure_logged_in(self) -> bool:
        """Re-authenticate if we don't have a valid access_token."""
        if self.access_token:
            # Optional: check expiry
            if self.token_expires_at:
                import time
                if time.time() > self.token_expires_at - 30:  # 30s buffer
                    logger.info("Access token expired, re-authenticating")
                    return self.authenticate()
            return True
        return self.authenticate()

    # ----- HTTP helpers -----

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Authenticated HTTP request to Vaultwarden."""
        url = f"{self.base_url}{path}"
        headers = kwargs.pop("headers", {})
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return self.session.request(method, url, headers=headers, **kwargs)

    def _log_response(self, op: str, resp: requests.Response):
        """Log HTTP response for debugging."""
        logger.info(
            f"{op}: HTTP {resp.status_code} "
            f"(body {len(resp.text)} chars, first 300: {resp.text[:300]!r})"
        )

    # ----- Vaultwarden encryption helpers -----

    def _derive_master_keys(self, password: str, email: str, kdf_iterations: int):
        """Derive the master encryption key from the user's master password.

        Returns BOTH v2 and v1 master keys so we can try both:
        - v2: HKDF(stretched, info="bitwarden-master-password-auth-v2")
        - v1: PBKDF2(stretched, email.lower(), 1)  [legacy]

        Common steps:
        1. password_hash = PBKDF2-SHA256(password, email.lower(), kdf_iterations)
        2. stretched_hash = PBKDF2-SHA256(password_hash, password_hash, 1)
        """
        # Diagnostic: log what we are using (no secrets!)
        logger.info(
            f"Key derivation: email={email!r} "
            f"email_lower={email.lower()!r} "
            f"kdf_iterations={kdf_iterations} "
            f"password_len={len(password)}"
        )
        password_hash = PBKDF2(
            password.encode("utf-8"),
            email.lower().encode("utf-8"),
            dkLen=32,
            count=kdf_iterations,
            hmac_hash_module=SHA256,
        )
        stretched = PBKDF2(
            password_hash,
            password_hash,
            dkLen=32,
            count=1,
            hmac_hash_module=SHA256,
        )
        # v2 (current): HKDF with info="bitwarden-master-password-auth-v2"
        master_key_v2 = HKDF(
            master=stretched,
            key_len=32,
            salt=b"",
            hashmod=SHA256,
            context=b"bitwarden-master-password-auth-v2",
        )
        # v1 (legacy): PBKDF2(stretched, email.lower(), 1)
        master_key_v1 = PBKDF2(
            stretched,
            email.lower().encode("utf-8"),
            dkLen=32,
            count=1,
            hmac_hash_module=SHA256,
        )
        # Diagnostic: log derived key lengths
        logger.info(
            f"Derived keys: password_hash_len={len(password_hash)} "
            f"stretched_len={len(stretched)} "
            f"mk_v2_len={len(master_key_v2)} "
            f"mk_v1_len={len(master_key_v1)}"
        )
        return master_key_v2, master_key_v1

    def _decrypt_enc_string(self, enc_string: str, key: bytes) -> Optional[str]:
        """Decrypt a Bitwarden/Vaultwarden encString.

        Supports two encString formats:
        - Bitwarden standard: "2.iv.ct" (AES-GCM, tag appended to ct)
        - Vaultwarden:       "2.iv|ct|tag" (AES-GCM, tag is separate)

        Both formats use version "2" for AES-256-GCM.
        """
        if not enc_string or not isinstance(enc_string, str):
            return None
        try:
            if "." not in enc_string:
                return None
            version, rest = enc_string.split(".", 1)

            # Detect format: "2.iv|ct|tag" (Vaultwarden, pipes) vs "2.iv.ct" (Bitwarden, dots)
            if "|" in rest:
                # Vaultwarden format: tag is a separate base64 chunk
                parts = rest.split("|")
                if len(parts) != 3:
                    return None
                iv = base64.b64decode(parts[0])
                ct = base64.b64decode(parts[1])
                tag = base64.b64decode(parts[2])
            else:
                # Bitwarden standard: tag is appended to ct (last 16 bytes)
                sub_parts = rest.split(".")
                if len(sub_parts) < 2:
                    return None
                iv = base64.b64decode(sub_parts[0])
                ct_combined = base64.b64decode("".join(sub_parts[1:]))
                if len(ct_combined) < 16:
                    return None
                ct = ct_combined[:-16]
                tag = ct_combined[-16:]

            if version == "2":  # AES-256-GCM
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(ct, tag)
                return plaintext.decode("utf-8")
            elif version == "0":  # AES-CBC-HMAC (legacy)
                logger.warning("AES-CBC-HMAC (version 0) decryption not implemented")
                return None
            else:
                logger.warning(f"Unknown encryption version: {version}")
                return None
        except Exception as e:
            logger.error(f"Decryption error for encString: {e}")
            return None

    def _decrypt_user_key(self, master_password_unlock, master_key: bytes) -> Optional[bytes]:
        """Decrypt the user encryption key (encKey) from masterPasswordUnlock.

        The decrypted plaintext is the full 64-byte user_key (encKey || macKey).
        For AES-GCM decryption we only need encKey (first 32 bytes).
        Storing the full 64 bytes would cause AES.new() to reject the key
        with "Incorrect AES key length".
        """
        # Normalize masterPasswordUnlock to a string (Vaultwarden may return dict/bytes/str)
        try:
            logger.info(
                f"_decrypt_user_key: master_password_unlock type={type(master_password_unlock).__name__} "
                f"is_truthy={bool(master_password_unlock)}"
            )
        except Exception:
            pass

        if not master_password_unlock:
            logger.warning("master_password_unlock is falsy (None/empty)")
            return None

        if isinstance(master_password_unlock, dict):
            logger.info(
                f"masterPasswordUnlock is a DICT with keys: {list(master_password_unlock.keys())}"
            )
            # New Bitwarden 2024+ format:
            # {"kdf": {...}, "masterKeyEncryptedUserKey": "...", "masterKeyWrappedUserKey": "...", "salt": "..."}
            if "masterKeyEncryptedUserKey" in master_password_unlock and "salt" in master_password_unlock:
                logger.info("Detected new Bitwarden 2024+ KDF format (salt + encrypted user key)")
                kdf_config = master_password_unlock.get("kdf", {})
                kdf_type = kdf_config.get("kdfType", 0)
                kdf_iterations = kdf_config.get("iterations", 600000)
                salt = master_password_unlock.get("salt", "")
                enc_user_key = master_password_unlock.get("masterKeyEncryptedUserKey", "")
                wrapped_user_key = master_password_unlock.get("masterKeyWrappedUserKey", "")
                logger.info(
                    f"KDF config: type={kdf_type} iterations={kdf_iterations} "
                    f"salt_len={len(str(salt))} enc_user_key_len={len(str(enc_user_key))}"
                )
                # Derive master_key using the explicit salt (NOT email)
                if not salt or not enc_user_key or not master_key:
                    logger.error("Missing salt, enc_user_key, or master_key")
                    return None
                try:
                    # Decode salt — Vaultwarden sends it as 20-char base64-like string with
                    # 3 non-alphabet chars (whitespace, BOM, or other JSON artifacts).
                    # Symptom: std b64decode strips 3 chars → 17 remain → 17 mod 4 = 1 → padding fail.
                    # urlsafe_b64decode (validate=True) also fails because it doesn't strip.
                    # FIX: strip non-alphabet chars FIRST, THEN pad to multiple of 4, THEN decode.
                    import re
                    salt_raw = salt if isinstance(salt, str) else str(salt)
                    salt_bytes = None
                    salt_format = None

                    # Diagnostic: log raw salt safely (first 8 + last 4 chars) to identify format
                    logger.info(
                        f"Salt raw: len={len(salt_raw)} type={type(salt).__name__} "
                        f"first8={salt_raw[:8] if isinstance(salt_raw, str) else 'n/a'!r} "
                        f"last4={salt_raw[-4:] if isinstance(salt_raw, str) else 'n/a'!r}"
                    )

                    # SPECIAL CASE: Vaultwarden sends an email-shaped value in the 'salt' field,
                    # but its local part may differ from self.user_email (Bug 2026-08-16:
                    # salt first8='usta.ai@' but user_email is something else).
                    # Fix: detect email-shaped salt, but use self.user_email.lower() (the actual
                    # configured user email) for PBKDF2 — same salt that legacy v1 derivation uses.
                    if (
                        isinstance(salt_raw, str)
                        and "@" in salt_raw
                        and "." in salt_raw.split("@")[-1]
                        and " " not in salt_raw
                    ):
                        salt_bytes = self.user_email.lower().encode("utf-8")
                        salt_format = "user-email-vaultwarden-quirk"
                        logger.info(
                            f"Salt field is email-shaped — using self.user_email.lower() as "
                            f"PBKDF2 salt: {len(salt_bytes)} bytes "
                            f"(vaultwarden salt field local-part may differ from user email)"
                        )
                    elif isinstance(salt_raw, bytes):
                        salt_bytes = salt_raw
                        salt_format = "bytes"
                    else:
                        # Strip chars NOT in either base64 alphabet (std or urlsafe)
                        cleaned = re.sub(r'[^A-Za-z0-9+/=\-_]', '', salt_raw)
                        stripped_count = len(salt_raw) - len(cleaned)
                        if stripped_count > 0:
                            logger.info(
                                f"Salt cleanup: stripped {stripped_count} non-base64 chars "
                                f"(was {len(salt_raw)}, now {len(cleaned)})"
                            )

                        # Try 1: standard base64 (with -_ treated as +/)
                        try:
                            padded = cleaned + "=" * (-len(cleaned) % 4)
                            salt_bytes = base64.b64decode(padded, altchars=b'-_')
                            salt_format = "std-base64"
                            logger.info(
                                f"Salt decoded (std-base64): {len(salt_bytes)} bytes "
                                f"(from {len(cleaned)} cleaned chars)"
                            )
                        except Exception as e_std:
                            # Try 2: URL-safe base64
                            try:
                                padded = cleaned + "=" * (-len(cleaned) % 4)
                                salt_bytes = base64.urlsafe_b64decode(padded)
                                salt_format = "urlsafe-base64"
                                logger.info(
                                    f"Salt decoded (urlsafe-base64): {len(salt_bytes)} bytes "
                                    f"(from {len(cleaned)} cleaned chars)"
                                )
                            except Exception as e_url:
                                # Try 3: hex (some Vaultwarden versions)
                                try:
                                    salt_bytes = bytes.fromhex(cleaned)
                                    salt_format = "hex"
                                    logger.info(
                                        f"Salt decoded (hex): {len(salt_bytes)} bytes "
                                        f"(from {len(cleaned)} cleaned chars)"
                                    )
                                except Exception as e_hex:
                                    # Last resort: raw UTF-8 bytes (likely wrong but won't crash)
                                    salt_bytes = salt_raw.encode("utf-8")
                                    salt_format = "raw-utf8"
                                    logger.warning(
                                        f"All salt decodes failed. "
                                        f"std={type(e_std).__name__}({e_std}), "
                                        f"urlsafe={type(e_url).__name__}({e_url}), "
                                        f"hex={type(e_hex).__name__}({e_hex}). "
                                        f"Using raw UTF-8 as fallback: {len(salt_bytes)} bytes"
                                    )
                    # Sanity: Bitwarden salts are typically 32 bytes; flag if way off
                    if salt_format and salt_bytes is not None and len(salt_bytes) < 16:
                        logger.warning(
                            f"Salt is only {len(salt_bytes)} bytes — Bitwarden expects 32. "
                            f"Format={salt_format}"
                        )

                    # v2: HKDF with auth-v2 info
                    password_hash = PBKDF2(
                        self.password.encode("utf-8"),
                        salt_bytes,
                        dkLen=32,
                        count=int(kdf_iterations),
                        hmac_hash_module=SHA256,
                    )
                    stretched = PBKDF2(
                        password_hash,
                        password_hash,
                        dkLen=32,
                        count=1,
                        hmac_hash_module=SHA256,
                    )
                    master_key_v2 = HKDF(
                        master=stretched,
                        key_len=32,
                        salt=b"",
                        hashmod=SHA256,
                        context=b"bitwarden-master-password-auth-v2",
                    )
                    # v1: PBKDF2(stretched, self.user_email.lower(), 1) — old style
                    # (self.user_email statt email, da email im Scope von _decrypt_user_key nicht verfügbar)
                    master_key_v1 = PBKDF2(
                        stretched,
                        self.user_email.lower().encode("utf-8"),
                        dkLen=32,
                        count=1,
                        hmac_hash_module=SHA256,
                    )
                    # Try v2 first, then v1
                    plaintext = self._decrypt_enc_string(str(enc_user_key), master_key_v2)
                    if plaintext is None:
                        logger.info("v2 failed, trying v1...")
                        plaintext = self._decrypt_enc_string(str(enc_user_key), master_key_v1)
                    if plaintext is None:
                        logger.error("Both v2 and v1 failed for enc_user_key")
                        return None
                    raw = plaintext.encode("latin-1") if isinstance(plaintext, str) else plaintext
                    if len(raw) >= 32:
                        logger.info(f"Decrypted user_key (new format): raw_len={len(raw)}")
                        return raw[:32]
                    logger.error(f"Decrypted user_key too short: {len(raw)}")
                    return None
                except Exception as e:
                    logger.error(f"Key derivation (new format) error: {e}")
                    return None
            # Legacy dict format
            mpu_str = (
                master_password_unlock.get("value")
                or master_password_unlock.get("data")
                or master_password_unlock.get("kdfPassword")
                or master_password_unlock.get("kdfKey")
                or ""
            )
            if not mpu_str:
                logger.error(
                    f"masterPasswordUnlock dict has no value/data/kdfPassword/kdfKey. "
                    f"Full dict: {master_password_unlock!r}"
                )
                return None
            logger.info(f"Extracted masterPasswordUnlock string from dict (len={len(str(mpu_str))})")
            mpu_str = str(mpu_str)
        elif isinstance(master_password_unlock, bytes):
            logger.info("masterPasswordUnlock is bytes, decoding to str")
            try:
                mpu_str = master_password_unlock.decode("utf-8")
            except Exception as e:
                logger.error(f"Failed to decode bytes: {e}")
                return None
        elif isinstance(master_password_unlock, str):
            mpu_str = master_password_unlock
        else:
            logger.error(
                f"masterPasswordUnlock has unexpected type: {type(master_password_unlock).__name__}"
            )
            return None

        if not mpu_str:
            logger.warning("masterPasswordUnlock string is empty after normalization")
            return None

        # Diagnostic: log format (no secret content!)
        try:
            mpu_starts = mpu_str[:6]
            mpu_version = mpu_str.split('.')[0] if '.' in mpu_str else '?'
            logger.info(
                f"masterPasswordUnlock format: starts={mpu_starts!r} "
                f"len={len(mpu_str)} version={mpu_version!r}"
            )
        except Exception as e:
            logger.error(f"masterPasswordUnlock format log error: {e}")

        plaintext = self._decrypt_enc_string(mpu_str, master_key)
        if not plaintext:
            logger.warning(
                f"masterPasswordUnlock decryption FAILED (returned None/empty) "
                f"with key_len={len(master_key) if master_key else 0}"
            )
            return None
        try:
            raw = plaintext.encode("latin-1") if isinstance(plaintext, str) else plaintext
            # Diagnostic: log decrypted plaintext length (expected 64 for user_key)
            # Diagnostic: log decrypted plaintext length (expected 64 for user_key)
            first_bytes = raw[:4].hex() if len(raw) >= 4 else 'too short'
            logger.info(
                f"Decrypted user_key: raw_len={len(raw)} expected=64 "
                f"first_bytes={first_bytes!r}"
            )
            if len(raw) >= 32:
                # Bitwarden user_key layout: [encKey 32B][macKey 32B] = 64B total
                # AES-GCM uses encKey (first 32 bytes) for encryption
                return raw[:32]
        except Exception as e:
            logger.error(f"User key extraction error: {e}")
        return None

    def _decrypt_cipher(self, cipher: Dict, user_key: bytes) -> Dict:
        """Decrypt all encrypted fields of a cipher using user_key. Returns dict with plaintext."""
        out = {
            "id": cipher.get("id"),
            "type": cipher.get("type"),
            "folderId": cipher.get("folderId"),
            "favorite": cipher.get("favorite", False),
            "organizationId": cipher.get("organizationId"),
            "collectionIds": cipher.get("collectionIds", []),
            "revisionDate": cipher.get("revisionDate"),
            "creationDate": cipher.get("creationDate"),
        }
        # Decrypt name
        name = cipher.get("name")
        if name and isinstance(name, str) and name[:1] in ("0", "2"):
            d = self._decrypt_enc_string(name, user_key)
            if d is not None:
                out["name"] = d
            else:
                out["name"] = name
        else:
            out["name"] = name
        # Decrypt notes
        notes = cipher.get("notes")
        if notes and isinstance(notes, str) and notes[:1] in ("0", "2"):
            d = self._decrypt_enc_string(notes, user_key)
            if d is not None:
                out["notes"] = d
        else:
            out["notes"] = notes
        # Decrypt login fields
        if cipher.get("login"):
            orig_login = cipher["login"]
            login = {}
            for field in ("username", "password", "totp"):
                val = orig_login.get(field)
                if val and isinstance(val, str) and val[:1] in ("0", "2"):
                    d = self._decrypt_enc_string(val, user_key)
                    login[field] = d if d is not None else val
                else:
                    login[field] = val
            # Decrypt URIs
            if orig_login.get("uris"):
                decrypted_uris = []
                for uri_obj in orig_login["uris"]:
                    if isinstance(uri_obj, dict):
                        uri = uri_obj.get("uri", "")
                        if uri and isinstance(uri, str) and uri[:1] in ("0", "2"):
                            d = self._decrypt_enc_string(uri, user_key)
                            new_obj = dict(uri_obj)
                            new_obj["uri"] = d if d is not None else uri
                        else:
                            new_obj = dict(uri_obj)
                        decrypted_uris.append(new_obj)
                login["uris"] = decrypted_uris
            out["login"] = login
        return out

    # ----- Item operations -----

    def search_items(self, query: str = None, item_type: str = None,
                    folder_id: str = None, limit: int = 20) -> List[BitwardenItem]:
        """Search items by query, type, folder.

        Vaultwarden returns all items via /api/sync (not /api/items).
        We fetch the full sync response, then filter the items array locally.
        Note: items are under the key "ciphers" (Bitwarden API convention),
        NOT "items" — that's why we use data.get("ciphers", ...).
        """
        if not self._ensure_logged_in():
            logger.error("search_items: not authenticated")
            return []

        try:
            resp = self._request("GET", "/api/sync", timeout=30)
            self._log_response("GET /api/sync", resp)
            if resp.status_code != 200:
                logger.error(f"GET /api/sync failed: {resp.status_code}")
                return []

            data = resp.json()
            # DIAGNOSE: log the response structure (top-level keys + their types)
            logger.info(f"/api/sync response keys: {list(data.keys())}")
            for key in data.keys():
                val = data[key]
                if isinstance(val, list):
                    logger.info(f"  {key}: list with {len(val)} items")
                elif isinstance(val, dict):
                    logger.info(f"  {key}: dict with keys {list(val.keys())[:5]}")
                else:
                    logger.info(f"  {key}: {type(val).__name__}")

            # Vaultwarden returns items under "ciphers" (Bitwarden API convention)
            items_data = data.get("ciphers", data.get("items", []))
            if not isinstance(items_data, list):
                logger.error(f"Unexpected items format in /api/sync: {type(items_data)}")
                return []

            target_type = self.TYPE_MAP.get(item_type.lower()) if item_type else None
            query_lower = query.lower() if query else None

            results: List[BitwardenItem] = []
            # Decrypt ciphers if we have user_key
            for item in items_data:
                # Decrypt if user_key available
                if self.user_key:
                    try:
                        item = self._decrypt_cipher(item, self.user_key)
                    except Exception as e:
                        logger.warning(f"Decrypt failed for cipher {item.get('id')}: {e}")
                        # Continue with encrypted data
                # Filter by type
                if target_type and item.get("type") != target_type:
                    continue
                # Filter by folder
                if folder_id and item.get("folderId") != folder_id:
                    continue
                # Filter by query (search name + username + URIs)
                if query_lower:
                    name = (item.get("name") or "").lower()
                    login = item.get("login") or {}
                    username = (login.get("username") or "").lower()
                    uris = " ".join(
                        u.get("uri", "") for u in login.get("uris", [])
                    ).lower()
                    haystack = f"{name} {username} {uris}"
                    if query_lower not in haystack:
                        continue
                parsed = self._parse_item(item)
                if parsed:
                    results.append(parsed)
                if len(results) >= limit:
                    break

            logger.info(f"search_items: found {len(results)} items "
                        f"(query={query!r}, type={item_type!r})")
            return results

        except Exception as e:
            logger.error(f"search_items error: {e}")
            return []

    def get_item(self, item_id: str) -> Optional[BitwardenItem]:
        """Get a specific item by ID. Decrypts if user_key is available."""
        if not self._ensure_logged_in():
            return None
        try:
            resp = self._request("GET", f"/api/ciphers/{item_id}", timeout=30)
            self._log_response(f"GET /api/ciphers/{item_id}", resp)
            if resp.status_code != 200:
                logger.error(f"GET /api/ciphers/{item_id} failed: {resp.status_code}")
                return None
            data = resp.json()
            # Decrypt if user_key available
            if self.user_key:
                try:
                    data = self._decrypt_cipher(data, self.user_key)
                except Exception as e:
                    logger.warning(f"Decrypt failed: {e}")
            return self._parse_item(data)
        except Exception as e:
            logger.error(f"get_item error: {e}")
            return None

    def create_login(self, name: str, username: str, password: str,
                    uris: List[str] = None, notes: str = None,
                    folder_id: str = None) -> Optional[str]:
        """Create a new login cipher. Returns new cipher ID or None.

        Note: Vaultwarden uses /api/ciphers for item operations, NOT /api/items.
        """
        if not self._ensure_logged_in():
            return None
        cipher_template = {
            "type": 1,  # Login
            "name": name,
            "login": {
                "username": username,
                "password": password,
                "uris": [{"uri": u} for u in (uris or [])],
            },
            "notes": notes or "",
        }
        if folder_id:
            cipher_template["folderId"] = folder_id
        try:
            # POST /api/ciphers (not /api/items!)
            resp = self._request("POST", "/api/ciphers", json=cipher_template, timeout=30)
            self._log_response("POST /api/ciphers", resp)
            if resp.status_code in (200, 201):
                return resp.json().get("id")
            logger.error(f"create_login failed: {resp.status_code} {resp.text[:200]!r}")
            return None
        except Exception as e:
            logger.error(f"create_login error: {e}")
            return None

    def create_note(self, name: str, content: str, folder_id: str = None) -> Optional[str]:
        """Create a new secure note. Returns new item ID or None."""
        if not self._ensure_logged_in():
            return None
        cipher_template = {
            "type": 2,  # SecureNote
            "name": name,
            "secureNote": {"type": 0},  # Generic
            "notes": content,
        }
        if folder_id:
            cipher_template["folderId"] = folder_id
        try:
            resp = self._request("POST", "/api/items", json=item_template, timeout=30)
            self._log_response("POST /api/items", resp)
            if resp.status_code in (200, 201):
                return resp.json().get("id")
            logger.error(f"create_note failed: {resp.status_code} {resp.text[:200]!r}")
            return None
        except Exception as e:
            logger.error(f"create_note error: {e}")
            return None

    def update_item(self, item_id: str, **kwargs) -> bool:
        """Update an existing item by ID."""
        if not self._ensure_logged_in():
            return False
        current = self.get_item(item_id)
        if not current:
            return False
        # Apply kwargs to current item
        if "name" in kwargs:
            current.name = kwargs["name"]
        if "username" in kwargs:
            current.username = kwargs["username"]
        if "password" in kwargs:
            current.password = kwargs["password"]
        if "uris" in kwargs:
            current.uris = kwargs["uris"]
        if "notes" in kwargs:
            current.notes = kwargs["notes"]
        if "folder_id" in kwargs:
            current.folder_id = kwargs["folder_id"]
        try:
            item_data = self._item_to_dict(current)
            resp = self._request("PUT", f"/api/ciphers/{item_id}", json=item_data, timeout=30)
            self._log_response(f"PUT /api/items/{item_id}", resp)
            return resp.status_code in (200, 204)
        except Exception as e:
            logger.error(f"update_item error: {e}")
            return False

    def delete_item(self, item_id: str) -> bool:
        """Delete an item by ID."""
        if not self._ensure_logged_in():
            return False
        try:
            resp = self._request("DELETE", f"/api/ciphers/{item_id}", timeout=30)
            self._log_response(f"DELETE /api/items/{item_id}", resp)
            return resp.status_code in (200, 204)
        except Exception as e:
            logger.error(f"delete_item error: {e}")
            return False

    # ----- Folder operations -----

    def list_folders(self) -> List[Dict[str, Any]]:
        """List all folders.

        Like items, folders are also fetched via /api/sync.
        Note: folders are under the key "folders" in the sync response.
        """
        if not self._ensure_logged_in():
            return []
        try:
            resp = self._request("GET", "/api/sync", timeout=30)
            self._log_response("GET /api/sync (folders)", resp)
            if resp.status_code != 200:
                return []
            data = resp.json()
            folders = data.get("folders", [])
            if not isinstance(folders, list):
                logger.warning(f"Unexpected folders format: {type(folders)}")
                return []
            return folders
        except Exception as e:
            logger.error(f"list_folders error: {e}")
            return []

    def create_folder(self, name: str) -> Optional[str]:
        """Create a new folder. Returns new folder ID or None."""
        if not self._ensure_logged_in():
            return None
        try:
            resp = self._request("POST", "/api/folders", json={"name": name}, timeout=30)
            self._log_response("POST /api/folders", resp)
            if resp.status_code in (200, 201):
                return resp.json().get("id")
            logger.error(f"create_folder failed: {resp.status_code} {resp.text[:200]!r}")
            return None
        except Exception as e:
            logger.error(f"create_folder error: {e}")
            return None

    # ----- Parsing helpers -----

    def _parse_item(self, item_data: Dict[str, Any]) -> Optional[BitwardenItem]:
        """Parse Vaultwarden item JSON into BitwardenItem dataclass."""
        if not item_data or "id" not in item_data:
            return None
        login = item_data.get("login") or {}
        try:
            return BitwardenItem(
                id=item_data["id"],
                name=item_data.get("name", ""),
                username=login.get("username"),
                password=login.get("password"),
                uris=[u.get("uri") for u in login.get("uris", []) if u.get("uri")],
                notes=item_data.get("notes"),
                folder_id=item_data.get("folderId"),
                type=item_data.get("type", 1),
                favorite=item_data.get("favorite", False),
            )
        except Exception as e:
            logger.error(f"_parse_item error: {e}")
            return None

    def _item_to_dict(self, item: BitwardenItem) -> Dict[str, Any]:
        """Convert BitwardenItem dataclass to Vaultwarden API JSON."""
        return {
            "type": item.type,
            "name": item.name,
            "login": {
                "username": item.username,
                "password": item.password,
                "uris": [{"uri": u} for u in (item.uris or []) if u],
            },
            "notes": item.notes or "",
            "folderId": item.folder_id,
            "favorite": item.favorite,
        }


def _get_client(base_url: str = None, api_key: str = None,
                email: str = None, password: str = None,
                client_secret: str = None) -> Optional[BitwardenCLIClient]:
    """Get authenticated Vaultwarden HTTP client."""
    try:
        url = base_url or DEFAULT_BASE_URL
        key = api_key or DEFAULT_API_KEY
        csecret = client_secret or DEFAULT_CLIENT_SECRET
        # Legacy fields (no longer required for HTTP client)
        user_email = email or DEFAULT_EMAIL
        user_password = password or DEFAULT_PASSWORD

        if not key:
            logger.error("Missing API key (BITWARDEN_CLIENT_ID env var)")
            return None

        client = BitwardenCLIClient(
            url,
            api_key=key,
            email=user_email,
            password=user_password,
            client_secret=csecret,
        )

        # Authenticate via OAuth2 client_credentials
        if not client.authenticate():
            logger.error("OAuth2 authentication failed")
            return None

        # No unlock_vault() needed — OAuth2 client_credentials returns
        # an access_token that's directly usable for /api/* calls.

        return client

    except Exception as e:
        logger.error(f"Failed to create client: {str(e)}")
        return None