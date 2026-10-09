"""Microsoft Entra OAuth for High Volume Email (HVE).

HVE authenticates to smtp.hve.mx.microsoft with SASL XOAUTH2. Two Entra
grant types are supported:

* Delegated: the HVE mailbox signs in once (device code or browser redirect)
  and SimpleRelay keeps the refresh token. This is the usual path.
* Application: client credentials, with a client secret or a certificate.
  No mailbox sign-in. The app needs Mail.Send application permission and
  Add-HVEAppAccess for that mailbox.

When the app registration uses a certificate, token requests send a
client assertion (JWT signed by that certificate) instead of a secret.
Refresh tokens are renewed 10 minutes early. HVE rejects a token that is
about to expire (501 5.5.127).
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from backend.config import settings
from backend.services.crypto import decrypt_password, encrypt_password

# Audience documented for HVE OAuth. `.default` uses the permissions
# already granted on the app registration. offline_access is what makes
# Microsoft return a refresh token for the mailbox sign-in.
DEFAULT_DELEGATED_SCOPE = "offline_access https://outlook.office.com/.default"
DEFAULT_APP_SCOPE = "https://outlook.office.com/.default"
HVE_REFRESH_SKEW = timedelta(seconds=600)

TOKEN_PATH = "/oauth2/v2.0/token"
DEVICE_PATH = "/oauth2/v2.0/devicecode"
AUTHORIZE_PATH = "/oauth2/v2.0/authorize"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# Microsoft error codes that will not succeed until an admin changes something
# or the mailbox signs in again.
_PERMANENT_ERRORS = {
    "invalid_grant",
    "invalid_client",
    "unauthorized_client",
    "access_denied",
    "authorization_declined",
    "interaction_required",
    "consent_required",
    "invalid_request",
}
# Refresh token is dead. Drop it so the UI asks for sign-in again.
_INVALIDATE_ERRORS = {"invalid_grant", "interaction_required", "consent_required"}

STATUS_NEEDS_SIGNIN = "needs_signin"
STATUS_PENDING = "pending"
STATUS_SIGNED_IN = "signed_in"
STATUS_APP = "app"
STATUS_ERROR = "error"


class MicrosoftOAuthError(Exception):
    def __init__(self, message: str, code: str | None = None, permanent: bool = False, invalidate: bool = False):
        super().__init__(message)
        self.code = code
        self.permanent = permanent
        self.invalidate = invalidate


def delegated_scope() -> str:
    custom = (settings.hve_scope or "").strip()
    return custom or DEFAULT_DELEGATED_SCOPE


def app_scope() -> str:
    return DEFAULT_APP_SCOPE


def token_endpoint(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}{TOKEN_PATH}"


def device_endpoint(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}{DEVICE_PATH}"


def authorize_endpoint(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}{AUTHORIZE_PATH}"


def redirect_uri() -> str:
    return settings.base_url.rstrip("/") + "/api/providers/hve/callback"


def server_hve_config() -> dict:
    """Public description of the Entra app configured via environment.

    Never includes the secret or the private key.
    """
    credential = None
    if _server_cert_paths():
        credential = "certificate"
    elif (settings.hve_client_secret or "").strip():
        credential = "secret"
    elif (settings.hve_client_id or "").strip():
        credential = "public"
    tenant = (settings.hve_tenant_id or "").strip()
    client = (settings.hve_client_id or "").strip()
    return {
        "configured": bool(tenant and client),
        "tenant_id": tenant,
        "client_id": client,
        "credential": credential,
        "redirect_uri": redirect_uri(),
        "smtp_host": "smtp.hve.mx.microsoft",
        "smtp_port": 587,
    }


def _server_cert_paths() -> tuple[Path, Path] | None:
    cert = (settings.hve_cert_file or "").strip()
    key = (settings.hve_key_file or "").strip()
    if not cert or not key:
        return None
    cert_path, key_path = Path(cert), Path(key)
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path
    return None


def _read_server_cert() -> tuple[str, str]:
    paths = _server_cert_paths()
    if not paths:
        raise MicrosoftOAuthError(
            "No certificate is configured on the server. Paste a PEM certificate and private key, "
            "or set RELAY_HVE_CERT_FILE and RELAY_HVE_KEY_FILE."
        )
    cert_pem = paths[0].read_text(encoding="utf-8")
    key_pem = paths[1].read_text(encoding="utf-8")
    return validate_certificate(cert_pem, key_pem)


def _guid(value: str, label: str) -> str:
    text = (value or "").strip()
    parts = text.split("-")
    ok = (
        len(parts) == 5
        and [len(p) for p in parts] == [8, 4, 4, 4, 12]
        and all(c in "0123456789abcdefABCDEF" for p in parts for c in p)
    )
    if not ok:
        raise MicrosoftOAuthError(f"{label} must be a GUID from the Entra app registration.")
    return text


def _clean(text: str) -> str:
    return " ".join((text or "").split())[:500]


_PEM_BLOCK = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----\s*.*?-----END (?P=label)-----",
    re.DOTALL,
)


def _pem_blocks(text: str) -> list[tuple[str, str]]:
    return [(match.group("label"), match.group(0).strip()) for match in _PEM_BLOCK.finditer(text or "")]


def _labeled_block(text: str, label: str) -> str:
    for found, block in _pem_blocks(text):
        if found == label:
            return block
    return ""


def _private_key_block(text: str) -> str:
    for found, block in _pem_blocks(text):
        if found == "PRIVATE KEY" or found.endswith(" PRIVATE KEY"):
            return block
    return ""


def validate_certificate(cert_pem: str, key_pem: str) -> tuple[str, str]:
    """Return normalized PEM certificate and unencrypted private key.

    The certificate must match the key. Entra has the public certificate;
    the thumbprint sent on the token request is computed from this one.
    A combined PEM, or a file with OpenSSL bag attributes, is accepted.
    """
    cert_text = (cert_pem or "").replace("\r\n", "\n").replace("\r", "\n")
    key_text = (key_pem or "").replace("\r\n", "\n").replace("\r", "\n")
    if len(cert_text) > 64000 or len(key_text) > 64000:
        raise MicrosoftOAuthError("Certificate or private key is too large.")
    # One downloaded file often holds both the certificate and the key.
    if _private_key_block(cert_text) and not _private_key_block(key_text):
        key_text = cert_text
    if _labeled_block(key_text, "CERTIFICATE") and not _labeled_block(cert_text, "CERTIFICATE"):
        cert_text = key_text
    cert_pem = _labeled_block(cert_text, "CERTIFICATE")
    key_pem = _private_key_block(key_text)
    if len(cert_pem) > 32000 or len(key_pem) > 32000:
        raise MicrosoftOAuthError("Certificate or private key is too large.")
    if not cert_pem:
        raise MicrosoftOAuthError("Certificate must be a PEM beginning with -----BEGIN CERTIFICATE-----.")
    if not key_pem:
        raise MicrosoftOAuthError("Private key must be an unencrypted PEM (BEGIN PRIVATE KEY or BEGIN RSA PRIVATE KEY).")
    if "ENCRYPTED" in key_pem:
        raise MicrosoftOAuthError("The private key is encrypted. Upload it without a passphrase.")
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        raise MicrosoftOAuthError("Could not read the certificate PEM.")
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except TypeError:
        raise MicrosoftOAuthError("The private key is encrypted. Upload it without a passphrase.")
    except Exception:
        raise MicrosoftOAuthError("Could not read the private key PEM.")
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise MicrosoftOAuthError("Certificate key must be RSA or EC.")
    cert_numbers = cert.public_key().public_numbers()
    key_numbers = key.public_key().public_numbers()
    if cert_numbers != key_numbers:
        raise MicrosoftOAuthError("The private key does not match this certificate.")
    cert_out = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_out = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_out, key_out


def certificate_thumbprint(cert_pem: str) -> str:
    """Base64url SHA-1 thumbprint (x5t) of the DER certificate. No padding."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA1())
    digest.update(der)
    raw = digest.finalize()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build_client_assertion(tenant_id: str, client_id: str, cert_pem: str, key_pem: str) -> str:
    cert_pem, key_pem = validate_certificate(cert_pem, key_pem)
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    now = int(time.time())
    token = jwt.encode(
        {
            "aud": token_endpoint(tenant_id),
            "iss": client_id,
            "sub": client_id,
            "jti": str(uuid.uuid4()),
            "nbf": now,
            "exp": now + 600,
        },
        key,
        algorithm="RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256",
        headers={"x5t": certificate_thumbprint(cert_pem)},
    )
    if isinstance(token, bytes):
        token = token.decode()
    return token


def client_auth_params(material: dict) -> dict:
    credential = material.get("credential") or "public"
    if credential == "secret":
        secret = (material.get("client_secret") or "").strip()
        if not secret:
            raise MicrosoftOAuthError(
                "Client secret is missing. Paste the Entra client secret, or set RELAY_HVE_CLIENT_SECRET.",
                code="invalid_client",
                permanent=True,
            )
        return {"client_secret": secret}
    if credential == "certificate":
        cert = material.get("certificate_pem") or ""
        key = material.get("private_key_pem") or ""
        if not cert or not key:
            raise MicrosoftOAuthError(
                "Certificate is missing. Paste the PEM certificate and private key, "
                "or set RELAY_HVE_CERT_FILE and RELAY_HVE_KEY_FILE.",
                code="invalid_client",
                permanent=True,
            )
        assertion = build_client_assertion(material["tenant_id"], material["client_id"], cert, key)
        return {
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        }
    return {}


def interpret_token_response(status_code: int, payload: dict, raw_text: str = "") -> dict:
    # Device-code responses are HTTP 200 and carry user_code, not access_token.
    if status_code == 200 and not payload.get("error"):
        return payload
    code = payload.get("error")
    description = payload.get("error_description") or raw_text or "Microsoft token request failed"
    raise MicrosoftOAuthError(
        _clean(description),
        code=code,
        permanent=code in _PERMANENT_ERRORS,
        invalidate=code in _INVALIDATE_ERRORS,
    )


def post_form(url: str, data: dict) -> dict:
    try:
        with httpx.Client(timeout=20) as client:
            response = client.post(url, data=data)
    except httpx.HTTPError as exc:
        raise MicrosoftOAuthError(f"Could not reach Microsoft login: {exc}", permanent=False)
    try:
        payload = response.json()
    except Exception:
        payload = {}
    return interpret_token_response(response.status_code, payload if isinstance(payload, dict) else {}, response.text)


def tokens_from_payload(payload: dict) -> dict:
    expires_in = int(payload.get("expires_in") or 3600)
    return {
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token") or "",
        "expires_at": datetime.utcnow() + timedelta(seconds=expires_in),
    }


def _as_naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def token_is_fresh(access_token: str | None, expires_at: datetime | None, now: datetime | None = None) -> bool:
    if not access_token or not expires_at:
        return False
    expires_at = _as_naive_utc(expires_at)
    now = now or datetime.utcnow()
    return expires_at - now > HVE_REFRESH_SKEW


def start_device_flow(tenant_id: str, client_id: str) -> dict:
    payload = post_form(device_endpoint(tenant_id), {
        "client_id": client_id,
        "scope": delegated_scope(),
    })
    return {
        "device_code": payload.get("device_code") or "",
        "user_code": payload.get("user_code") or "",
        "verification_uri": (
            payload.get("verification_uri")
            or payload.get("verification_url")
            or "https://microsoft.com/devicelogin"
        ),
        "expires_in": int(payload.get("expires_in") or 900),
        "interval": int(payload.get("interval") or 5),
        "message": payload.get("message") or "",
    }


def redeem_device_code(material: dict, device_code: str) -> dict:
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": material["client_id"],
        "device_code": device_code,
        "scope": delegated_scope(),
    }
    data.update(client_auth_params(material))
    return tokens_from_payload(post_form(token_endpoint(material["tenant_id"]), data))


def redeem_auth_code(material: dict, code: str, code_verifier: str) -> dict:
    data = {
        "grant_type": "authorization_code",
        "client_id": material["client_id"],
        "code": code,
        "redirect_uri": redirect_uri(),
        "scope": delegated_scope(),
        "code_verifier": code_verifier,
    }
    data.update(client_auth_params(material))
    return tokens_from_payload(post_form(token_endpoint(material["tenant_id"]), data))


def refresh_delegated(material: dict) -> dict:
    refresh = (material.get("refresh_token") or "").strip()
    if not refresh:
        raise MicrosoftOAuthError(
            "Sign in to the HVE account first.",
            code="sign_in_required",
            permanent=False,
        )
    # Microsoft rejects a refresh that omits scope (AADSTS900144).
    data = {
        "grant_type": "refresh_token",
        "client_id": material["client_id"],
        "refresh_token": refresh,
        "scope": delegated_scope(),
    }
    data.update(client_auth_params(material))
    return tokens_from_payload(post_form(token_endpoint(material["tenant_id"]), data))


def fetch_client_credentials(material: dict) -> dict:
    data = {
        "grant_type": "client_credentials",
        "client_id": material["client_id"],
        "scope": app_scope(),
    }
    data.update(client_auth_params(material))
    return tokens_from_payload(post_form(token_endpoint(material["tenant_id"]), data))


def ensure_access_token(material: dict, now: datetime | None = None) -> tuple[str, dict | None]:
    """Return (access_token, updates). updates is None when the cached token is still fresh.

    updates contains plaintext tokens. The caller encrypts them before saving.
    """
    if token_is_fresh(material.get("access_token"), material.get("expires_at"), now=now):
        return material["access_token"], None
    if material.get("mode") == "application":
        tokens = fetch_client_credentials(material)
    else:
        tokens = refresh_delegated(material)
    updates = {
        "access_token": tokens["access_token"],
        "expires_at": tokens["expires_at"],
    }
    if tokens.get("refresh_token"):
        updates["refresh_token"] = tokens["refresh_token"]
    return tokens["access_token"], updates


def build_authorize_url(material: dict, state: str, code_challenge: str, login_hint: str | None) -> str:
    params = {
        "client_id": material["client_id"],
        "response_type": "code",
        "redirect_uri": redirect_uri(),
        "response_mode": "query",
        "scope": delegated_scope(),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    if login_hint:
        params["login_hint"] = login_hint
    return authorize_endpoint(material["tenant_id"]) + "?" + urlencode(params)


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def make_state(provider_id: int) -> str:
    token = jwt.encode(
        {"pid": provider_id, "purpose": "hve", "exp": int(time.time()) + 600},
        settings.secret_key,
        algorithm="HS256",
    )
    if isinstance(token, bytes):
        token = token.decode()
    return token


def read_state(state: str) -> int:
    try:
        payload = jwt.decode(state, settings.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise MicrosoftOAuthError("Sign-in session expired. Start it again from SimpleRelay.")
    if payload.get("purpose") != "hve" or not payload.get("pid"):
        raise MicrosoftOAuthError("Sign-in session was not valid.")
    return int(payload["pid"])


def _decrypt_field(value: str | None) -> str:
    if not value:
        return ""
    try:
        return decrypt_password(value)
    except Exception:
        raise MicrosoftOAuthError(
            "Cannot decrypt the stored HVE credential. Check RELAY_SECRET_KEY, then enter the certificate or secret again and sign in.",
            code="decrypt_failed",
            permanent=True,
        )


def _record_get(record, key: str):
    if isinstance(record, dict):
        return record.get(key)
    return getattr(record, key, None)


def material_from_record(record) -> dict:
    expires = _record_get(record, "oauth_token_expires_at")
    return {
        "tenant_id": (_record_get(record, "oauth_tenant_id") or "").strip(),
        "client_id": (_record_get(record, "oauth_client_id") or "").strip(),
        "credential": _record_get(record, "oauth_credential") or "public",
        "mode": _record_get(record, "oauth_mode") or "delegated",
        "client_secret": _decrypt_field(_record_get(record, "oauth_client_secret_encrypted")),
        "certificate_pem": _decrypt_field(_record_get(record, "oauth_cert_pem_encrypted")),
        "private_key_pem": _decrypt_field(_record_get(record, "oauth_key_pem_encrypted")),
        "refresh_token": _decrypt_field(_record_get(record, "oauth_refresh_token_encrypted")),
        "access_token": _decrypt_field(_record_get(record, "oauth_access_token_encrypted")),
        "expires_at": expires,
    }


def encrypt_token_updates(updates: dict) -> dict:
    """Map plaintext token updates to encrypted provider columns."""
    allowed = {}
    if updates.get("access_token"):
        allowed["oauth_access_token_encrypted"] = encrypt_password(updates["access_token"])
    if updates.get("refresh_token"):
        allowed["oauth_refresh_token_encrypted"] = encrypt_password(updates["refresh_token"])
    if "expires_at" in updates:
        allowed["oauth_token_expires_at"] = updates["expires_at"]
    return allowed


def apply_token_updates(provider, updates: dict) -> None:
    for column, value in encrypt_token_updates(updates).items():
        setattr(provider, column, value)


def resolve_hve_on_create(
    tenant_id: str | None,
    client_id: str | None,
    oauth_credential: str | None,
    oauth_mode: str | None,
    client_secret: str | None,
    certificate_pem: str | None,
    private_key_pem: str | None,
) -> dict:
    """Validate Entra settings and return provider column values."""
    server = server_hve_config()
    tenant = _guid(tenant_id or server["tenant_id"], "Directory (tenant) ID")
    client = _guid(client_id or server["client_id"], "Application (client) ID")
    requested = (oauth_credential or "certificate").strip().lower()
    if requested != "certificate":
        raise MicrosoftOAuthError("HVE uses a certificate for the Entra application.")
    mode = (oauth_mode or "delegated").strip().lower()
    if mode not in ("delegated", "application"):
        raise MicrosoftOAuthError("Authentication mode must be delegated or application.")

    cert = (certificate_pem or "").strip()
    key = (private_key_pem or "").strip()
    if not cert and not key:
        cert, key = _read_server_cert()
    else:
        cert, key = validate_certificate(cert, key)

    return {
        "oauth_tenant_id": tenant,
        "oauth_client_id": client,
        "oauth_credential": "certificate",
        "oauth_mode": mode,
        "oauth_status": STATUS_APP if mode == "application" else STATUS_NEEDS_SIGNIN,
        "oauth_client_secret_encrypted": None,
        "oauth_cert_pem_encrypted": encrypt_password(cert),
        "oauth_key_pem_encrypted": encrypt_password(key),
    }


def apply_hve_update(provider, payload: dict) -> bool:
    """Update Entra fields on an existing HVE provider.

    Returns True when credentials changed and stored mailbox tokens were cleared.
    Empty secret and certificate fields keep the values already saved.
    """
    tenant = _guid(payload.get("tenant_id") or provider.oauth_tenant_id, "Directory (tenant) ID")
    client = _guid(payload.get("client_id") or provider.oauth_client_id, "Application (client) ID")
    requested = (payload.get("oauth_credential") or "certificate").strip().lower()
    if requested != "certificate":
        raise MicrosoftOAuthError("HVE uses a certificate for the Entra application.")
    credential = "certificate"
    mode = (payload.get("oauth_mode") or provider.oauth_mode or "delegated").strip().lower()
    if mode not in ("delegated", "application"):
        raise MicrosoftOAuthError("Authentication mode must be delegated or application.")

    new_cert = (payload.get("certificate_pem") or "").strip()
    new_key = (payload.get("private_key_pem") or "").strip()
    replaced_cert = False

    if new_cert or new_key:
        cert, key = validate_certificate(new_cert, new_key)
        same = False
        if provider.oauth_cert_pem_encrypted and provider.oauth_key_pem_encrypted:
            try:
                same = (
                    decrypt_password(provider.oauth_cert_pem_encrypted) == cert
                    and decrypt_password(provider.oauth_key_pem_encrypted) == key
                )
            except Exception:
                same = False
        if not same:
            provider.oauth_cert_pem_encrypted = encrypt_password(cert)
            provider.oauth_key_pem_encrypted = encrypt_password(key)
            replaced_cert = True
    elif not provider.oauth_cert_pem_encrypted or not provider.oauth_key_pem_encrypted:
        cert, key = _read_server_cert()
        provider.oauth_cert_pem_encrypted = encrypt_password(cert)
        provider.oauth_key_pem_encrypted = encrypt_password(key)
        replaced_cert = True
    provider.oauth_client_secret_encrypted = None

    changed = (
        tenant != (provider.oauth_tenant_id or "")
        or client != (provider.oauth_client_id or "")
        or credential != (provider.oauth_credential or "")
        or mode != (provider.oauth_mode or "")
        or replaced_cert
    )
    provider.oauth_tenant_id = tenant
    provider.oauth_client_id = client
    provider.oauth_credential = credential
    provider.oauth_mode = mode
    if changed:
        clear_mailbox_tokens(provider)
        provider.oauth_status = STATUS_APP if mode == "application" else STATUS_NEEDS_SIGNIN
    elif mode == "application":
        provider.oauth_status = STATUS_APP
    return changed


def clear_mailbox_tokens(provider) -> None:
    provider.oauth_refresh_token_encrypted = None
    provider.oauth_access_token_encrypted = None
    provider.oauth_token_expires_at = None
    provider.oauth_device_code_encrypted = None
    provider.oauth_device_expires_at = None
    provider.oauth_pkce_verifier_encrypted = None
    provider.oauth_user_code = None
    provider.oauth_verification_uri = None


def store_mailbox_tokens(provider, tokens: dict) -> None:
    apply_token_updates(provider, tokens)
    provider.oauth_status = STATUS_SIGNED_IN
    provider.oauth_device_code_encrypted = None
    provider.oauth_device_expires_at = None
    provider.oauth_pkce_verifier_encrypted = None
    provider.oauth_user_code = None
    provider.oauth_verification_uri = None
    provider.last_error = None
