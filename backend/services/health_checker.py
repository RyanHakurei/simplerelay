"""Periodically check health of configured providers via SMTP AUTH login."""
import asyncio
import ssl
import time
import aiosmtplib
from datetime import datetime
from sqlalchemy import update
from sqlalchemy.orm import object_session
from backend.database import SessionLocal
from backend.models import Provider, HealthCheck, ProviderStatus
from backend.services.crypto import decrypt_password
from backend.services.microsoft_oauth import (
    MicrosoftOAuthError,
    apply_token_updates,
    ensure_access_token,
    material_from_record,
)
from backend.services.xoauth2_smtp import probe_xoauth2


def _flush_provider(provider: Provider) -> None:
    """Write token changes before the status update, which does not include them."""
    session = object_session(provider)
    if session is not None:
        session.flush()


def _make_tls_context():
    """Create TLS context that accepts self-signed / invalid certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def check_provider(provider: Provider) -> tuple[bool, int | None, str | None]:
    """Test SMTP connection + AUTH login to a provider.
    Returns (healthy, response_time_ms, error).
    """
    start = time.monotonic()
    if provider.provider_type == "microsoft_hve":
        return await _check_hve(provider, start)

    try:
        use_tls = provider.tls_mode == "ssl"
        start_tls = provider.tls_mode == "starttls"
        tls_context = _make_tls_context() if (use_tls or start_tls) else None

        smtp = aiosmtplib.SMTP(
            hostname=provider.smtp_host,
            port=provider.smtp_port,
            use_tls=use_tls,
            start_tls=start_tls,
            tls_context=tls_context,
            timeout=15,
        )
        await smtp.connect()

        # Real AUTH login — not just EHLO
        if provider.username and provider.password_encrypted:
            try:
                password = decrypt_password(provider.password_encrypted)
            except Exception:
                password = provider.password_encrypted
            await smtp.login(provider.username, password)

        await smtp.quit()

        elapsed = int((time.monotonic() - start) * 1000)
        return True, elapsed, None

    except Exception as e:
        elapsed = int((time.monotonic() - start) * 1000)
        return False, elapsed, str(e)


async def _check_hve(provider: Provider, start: float) -> tuple[bool, int | None, str | None]:
    """Fetch an HVE access token and AUTH XOAUTH2. Does not send a message."""
    try:
        material = material_from_record(provider)
        token, updates = await asyncio.to_thread(ensure_access_token, material)
        if updates:
            apply_token_updates(provider, updates)
            provider.oauth_status = "app" if provider.oauth_mode == "application" else "signed_in"
            _flush_provider(provider)
        await asyncio.to_thread(
            probe_xoauth2,
            provider.smtp_host,
            provider.smtp_port,
            provider.tls_mode,
            provider.email,
            token,
        )
        elapsed = int((time.monotonic() - start) * 1000)
        return True, elapsed, None
    except MicrosoftOAuthError as exc:
        if exc.invalidate:
            provider.oauth_refresh_token_encrypted = None
            provider.oauth_access_token_encrypted = None
            provider.oauth_token_expires_at = None
            provider.oauth_status = "error"
            _flush_provider(provider)
        elapsed = int((time.monotonic() - start) * 1000)
        if exc.code == "sign_in_required":
            return False, elapsed, f"sign_in_required: {exc}"
        return False, elapsed, str(exc)[:500]
    except Exception as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        detail = str(exc)[:300]
        if "535" in detail or "Authentication" in detail:
            detail += (
                " HVE rejected the OAuth token. Sign in as the HVE mailbox, "
                "or grant Mail.Send and Add-HVEAppAccess for application permission."
            )
        return False, elapsed, detail[:500]


async def run_health_checks():
    """Check all active providers."""
    db = SessionLocal()
    try:
        providers = db.query(Provider).filter(
            Provider.status != ProviderStatus.DISABLED
        ).all()

        for provider in providers:
            healthy, response_time, error = await check_provider(provider)

            # Log health check
            check = HealthCheck(
                provider_id=provider.id,
                is_healthy=healthy,
                response_time_ms=response_time,
                error_message=error,
                checked_at=datetime.utcnow(),
            )
            db.add(check)

            # Missing HVE sign-in is not a dead provider. Leave it active so mail
            # stays queued and the dashboard can still start sign-in.
            if error and error.startswith("sign_in_required"):
                if provider.status in (ProviderStatus.ACTIVE, ProviderStatus.ERROR):
                    new_status = ProviderStatus.ACTIVE
                else:
                    new_status = provider.status
                error = error.split(":", 1)[1].strip()
            else:
                new_status = ProviderStatus.ACTIVE if healthy else ProviderStatus.ERROR
            db.execute(
                update(Provider)
                .where(Provider.id == provider.id)
                .values(
                    status=new_status,
                    last_health_check=datetime.utcnow(),
                    last_error=error,
                )
            )

        db.commit()
    finally:
        db.close()


async def main():
    """Run health checks in a loop every 5 minutes."""
    await asyncio.sleep(15)  # wait for DB init
    while True:
        try:
            await run_health_checks()
        except Exception as e:
            print(f"Health check error: {e}")
        await asyncio.sleep(300)


if __name__ == "__main__":
    asyncio.run(main())