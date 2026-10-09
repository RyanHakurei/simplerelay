"""Postfix SMTP policy server — SMTP AUTH bound to the envelope sender.

Postfix queries this server at RCPT TO time via:
  check_policy_service inet:127.0.0.1:9199

Any client IP may connect. Mail is accepted only when the SASL username
belongs to an active SMTP login for the provider that will send that mail.
Localhost is always allowed so the dashboard test can inject mail.

Protocol: Postfix SMTPD policy (attribute=value pairs, blank line terminated)
  Request attributes: client_address, sender, sasl_username, ...
  Response: action=permit | action=reject <reason>
"""
import socketserver
import logging
import sys

sys.path.insert(0, "/app")

from backend.config import settings
from backend.database import SessionLocal
from backend.models import AllowedClient, Provider, ProviderStatus
from backend.services.smtp_access import client_can_send, provider_for_sender

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="access_server: %(message)s",
)
log = logging.getLogger(__name__)


def _load_rules():
    """Active providers and SMTP logins. Read on every check so a new login works immediately."""
    db = SessionLocal()
    try:
        provider_rows = db.query(Provider).filter(
            Provider.is_locked == False,
            Provider.status == ProviderStatus.ACTIVE,
        ).all()
        providers = [
            {
                "id": row.id,
                "email": row.email,
                "domain_routing": bool(row.domain_routing),
                "user_id": row.user_id,
            }
            for row in provider_rows
        ]
        client_rows = db.query(AllowedClient).filter(
            AllowedClient.client_type == "smtp_auth",
            AllowedClient.is_active == True,
        ).all()
        clients = [
            {
                "smtp_username": row.smtp_username,
                "provider_id": row.provider_id,
                "user_id": row.user_id,
            }
            for row in client_rows
        ]
        return providers, clients
    finally:
        db.close()


def check_access(client_ip_str, sender, sasl_username):
    """Return (allowed, reason). A database error denies the message."""
    if client_ip_str in ("127.0.0.1", "::1"):
        return True, "localhost"
    if not sender:
        return False, "missing sender"
    if not (sasl_username or "").strip():
        return False, "SMTP authentication required"

    try:
        providers, clients = _load_rules()
    except Exception as e:
        log.error(f"DB error loading SMTP logins: {e}")
        return False, "access check failed"

    provider = provider_for_sender(sender, providers)
    if not provider:
        return False, f"no relay for sender {sender}"
    if client_can_send(sasl_username, settings.hostname, provider, clients):
        return True, f"smtp auth {sasl_username.strip().lower()}"
    return False, "SMTP login is not allowed for this sender"


class PolicyHandler(socketserver.StreamRequestHandler):
    """Handle Postfix SMTPD policy protocol."""

    def handle(self):
        while True:
            attrs = {}
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                line = line.decode().strip()
                if not line:
                    break
                if "=" in line:
                    key, _, value = line.partition("=")
                    attrs[key] = value

            if not attrs:
                return

            client_ip = attrs.get("client_address", "")
            sender = attrs.get("sender", "")
            sasl_username = attrs.get("sasl_username", "")

            allowed, reason = check_access(client_ip, sender, sasl_username)

            if allowed:
                action = "permit"
                log.info(f"PERMIT {client_ip} sasl={sasl_username or '-'} → {sender} ({reason})")
            else:
                action = f"reject {reason}"
                log.info(f"REJECT {client_ip} sasl={sasl_username or '-'} → {sender} ({reason})")

            self.wfile.write(f"action={action}\n\n".encode())
            self.wfile.flush()


def main():
    host, port = "127.0.0.1", 9199
    server = socketserver.ThreadingTCPServer((host, port), PolicyHandler)
    server.daemon_threads = True
    log.info(f"Policy server listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
