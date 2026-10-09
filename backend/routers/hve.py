"""Sign-in flow for Microsoft 365 High Volume Email mailboxes."""
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Provider, User
from backend.services.auth import get_current_user
from backend.services.crypto import decrypt_password, encrypt_password
from backend.services.microsoft_oauth import (
    MicrosoftOAuthError,
    STATUS_APP,
    STATUS_NEEDS_SIGNIN,
    STATUS_PENDING,
    apply_hve_update,
    build_authorize_url,
    clear_mailbox_tokens,
    make_pkce,
    make_state,
    material_from_record,
    read_state,
    redeem_auth_code,
    redeem_device_code,
    server_hve_config,
    start_device_flow,
    store_mailbox_tokens,
)
from backend.routers.providers import ProviderOut

router = APIRouter(prefix="/api/providers", tags=["hve"])

# Last time we called Microsoft for a device-code poll, per provider.
_last_poll: dict[int, float] = {}
_poll_guard = threading.Lock()
_poll_locks: dict[int, threading.Lock] = {}


def _provider_poll_lock(provider_id: int) -> threading.Lock:
    with _poll_guard:
        lock = _poll_locks.get(provider_id)
        if lock is None:
            lock = threading.Lock()
            _poll_locks[provider_id] = lock
        return lock


def _signed_in_payload(provider: Provider) -> dict:
    return {"status": "signed_in", "oauth_signed_in": bool(provider.oauth_signed_in)}


class HveUpdate(BaseModel):
    tenant_id: str | None = None
    client_id: str | None = None
    oauth_credential: str | None = None
    oauth_mode: str | None = None
    client_secret: str | None = None
    certificate_pem: str | None = None
    private_key_pem: str | None = None


def _hve_provider(db: Session, provider_id: int, user: User) -> Provider:
    provider = db.query(Provider).filter(
        Provider.id == provider_id,
        Provider.user_id == user.id,
    ).first()
    if not provider:
        raise HTTPException(404, "Provider not found")
    if provider.provider_type != "microsoft_hve":
        raise HTTPException(400, "This provider is not a Microsoft 365 HVE account")
    return provider


def _pending_payload(provider: Provider) -> dict:
    return {
        "status": "pending",
        "user_code": provider.oauth_user_code,
        "verification_uri": provider.oauth_verification_uri or "https://microsoft.com/devicelogin",
        "interval": provider.oauth_poll_interval or 5,
        "expires_at": provider.oauth_device_expires_at.isoformat() if provider.oauth_device_expires_at else None,
    }


@router.get("/hve/config")
def hve_config(user: User = Depends(get_current_user)):
    """Entra app configured on the server, if any. No secrets."""
    return server_hve_config()


@router.patch("/{provider_id}/hve", response_model=ProviderOut)
def update_hve(
    provider_id: int,
    data: HveUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    provider = _hve_provider(db, provider_id, user)
    try:
        apply_hve_update(provider, data.model_dump())
    except MicrosoftOAuthError as exc:
        raise HTTPException(400, str(exc))
    db.commit()
    db.refresh(provider)
    return provider


@router.post("/{provider_id}/hve/device")
def start_device_signin(
    provider_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Start a device-code sign-in. The user enters the code at microsoft.com/devicelogin."""
    provider = _hve_provider(db, provider_id, user)
    if provider.oauth_mode == "application":
        raise HTTPException(400, "This HVE provider uses application permission and does not sign in as a mailbox.")
    try:
        material = material_from_record(provider)
        flow = start_device_flow(material["tenant_id"], material["client_id"])
    except MicrosoftOAuthError as exc:
        raise HTTPException(400, str(exc))
    if not flow["device_code"] or not flow["user_code"]:
        raise HTTPException(502, "Microsoft did not return a sign-in code.")

    provider.oauth_device_code_encrypted = encrypt_password(flow["device_code"])
    provider.oauth_user_code = flow["user_code"]
    provider.oauth_verification_uri = flow["verification_uri"]
    provider.oauth_poll_interval = max(flow["interval"], 5)
    provider.oauth_device_expires_at = datetime.utcnow() + timedelta(seconds=flow["expires_in"])
    provider.oauth_status = STATUS_PENDING
    provider.last_error = None
    db.commit()
    _last_poll.pop(provider.id, None)
    return _pending_payload(provider)


@router.get("/{provider_id}/hve/device")
def poll_device_signin(
    provider_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """One poll of the device-code sign-in. Call again after `interval` seconds."""
    provider = _hve_provider(db, provider_id, user)
    # One redeem at a time. A second poll of the same device code is not a second sign-in.
    lock = _provider_poll_lock(provider.id)
    if not lock.acquire(blocking=False):
        return _pending_payload(provider)
    try:
        db.refresh(provider)
        if provider.oauth_mode == "application":
            return {"status": "app", "oauth_signed_in": bool(provider.oauth_signed_in)}
        if provider.oauth_signed_in:
            return _signed_in_payload(provider)
        if not provider.oauth_device_code_encrypted:
            return {"status": "idle", "oauth_signed_in": False}
        if provider.oauth_device_expires_at and provider.oauth_device_expires_at < datetime.utcnow():
            provider.oauth_device_code_encrypted = None
            provider.oauth_user_code = None
            provider.oauth_status = STATUS_NEEDS_SIGNIN
            db.commit()
            return {"status": "error", "error": "That code expired. Start sign-in again.", "oauth_signed_in": False}

        wait = provider.oauth_poll_interval or 5
        now = time.monotonic()
        if now - _last_poll.get(provider.id, 0) < wait:
            return _pending_payload(provider)

        _last_poll[provider.id] = now
        try:
            device_code = decrypt_password(provider.oauth_device_code_encrypted)
            material = material_from_record(provider)
            tokens = redeem_device_code(material, device_code)
        except MicrosoftOAuthError as exc:
            if exc.code in ("authorization_pending", "slow_down"):
                if exc.code == "slow_down":
                    provider.oauth_poll_interval = (provider.oauth_poll_interval or 5) + 5
                    db.commit()
                return _pending_payload(provider)
            provider.last_error = str(exc)[:500]
            provider.oauth_status = "error"
            if exc.code in (
                "expired_token",
                "bad_verification_code",
                "authorization_declined",
                "access_denied",
                "no_refresh_token",
            ):
                provider.oauth_device_code_encrypted = None
                provider.oauth_user_code = None
                provider.oauth_status = STATUS_NEEDS_SIGNIN
            db.commit()
            return {"status": "error", "error": str(exc), "oauth_signed_in": bool(provider.oauth_signed_in)}

        store_mailbox_tokens(provider, tokens)
        db.commit()
        _last_poll.pop(provider.id, None)
        return _signed_in_payload(provider)
    finally:
        lock.release()


@router.post("/{provider_id}/hve/redirect")
def start_browser_signin(
    provider_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Browser sign-in. Register the returned redirect URI on the Entra app."""
    provider = _hve_provider(db, provider_id, user)
    if provider.oauth_mode == "application":
        raise HTTPException(400, "This HVE provider uses application permission and does not sign in as a mailbox.")
    try:
        material = material_from_record(provider)
        verifier, challenge = make_pkce()
        state = make_state(provider.id)
        url = build_authorize_url(material, state, challenge, provider.email)
    except MicrosoftOAuthError as exc:
        raise HTTPException(400, str(exc))
    provider.oauth_pkce_verifier_encrypted = encrypt_password(verifier)
    provider.oauth_status = STATUS_PENDING
    db.commit()
    return {"authorize_url": url, "redirect_uri": server_hve_config()["redirect_uri"]}


@router.get("/hve/callback")
def browser_signin_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    """Microsoft redirects the browser here after the HVE mailbox signs in."""
    if error:
        message = quote((error_description or error)[:300])
        return RedirectResponse(f"/providers?hve=error&message={message}")
    if not code or not state:
        return RedirectResponse("/providers?hve=error&message=Missing%20sign-in%20response")
    try:
        provider_id = read_state(state)
    except MicrosoftOAuthError as exc:
        return RedirectResponse(f"/providers?hve=error&message={quote(str(exc)[:300])}")

    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider or provider.provider_type != "microsoft_hve":
        return RedirectResponse("/providers?hve=error&message=HVE%20provider%20not%20found")
    if not provider.oauth_pkce_verifier_encrypted:
        return RedirectResponse("/providers?hve=error&message=Sign-in%20session%20expired")
    try:
        verifier = decrypt_password(provider.oauth_pkce_verifier_encrypted)
        material = material_from_record(provider)
        tokens = redeem_auth_code(material, code, verifier)
    except MicrosoftOAuthError as exc:
        provider.last_error = str(exc)[:500]
        provider.oauth_status = "error"
        db.commit()
        return RedirectResponse(f"/providers?hve=error&message={quote(str(exc)[:300])}")

    store_mailbox_tokens(provider, tokens)
    db.commit()
    return RedirectResponse("/providers?hve=ok")


@router.post("/{provider_id}/hve/sign-out")
def sign_out_hve(
    provider_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    provider = _hve_provider(db, provider_id, user)
    clear_mailbox_tokens(provider)
    provider.oauth_status = STATUS_APP if provider.oauth_mode == "application" else STATUS_NEEDS_SIGNIN
    db.commit()
    _last_poll.pop(provider.id, None)
    return {"status": provider.oauth_status}
