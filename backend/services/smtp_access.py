"""Inbound relay access: SMTP login only.

Any client IP may connect. Mail from outside localhost is accepted only when
the SASL username is an active smtp_auth client for the provider that owns
the envelope sender. That is what keeps the relay from being open.
"""


def sasl_username_matches(presented, stored, hostname=""):
    """True when the login Postfix saw is this stored SMTP username.

    Cyrus may append @relay-hostname. A username that itself contains no @
    still matches that form. An email-shaped username matches only itself,
    or itself plus the relay hostname.
    """
    presented_name = (presented or "").strip().lower()
    stored_name = (stored or "").strip().lower()
    if not presented_name or not stored_name:
        return False
    if presented_name == stored_name:
        return True

    host = (hostname or "").strip().lower()
    if host and presented_name == f"{stored_name}@{host}":
        return True

    if "@" not in stored_name and "@" in presented_name:
        local, _, realm = presented_name.partition("@")
        if local == stored_name and (not host or realm == host):
            return True
    return False


def provider_for_sender(sender, providers):
    """Pick the provider the pipe will use for this envelope sender.

    Exact email wins. Otherwise the first domain-routing provider for that
    domain. Email equality is case-sensitive, matching lookup_provider.
    """
    if not sender:
        return None
    for provider in providers:
        if provider.get("email") == sender:
            return provider
    if "@" not in sender:
        return None
    domain = sender.split("@", 1)[1].lower()
    for provider in providers:
        email = provider.get("email") or ""
        if "@" not in email:
            continue
        if provider.get("domain_routing") and email.split("@", 1)[1].lower() == domain:
            return provider
    return None


def client_can_send(sasl_username, hostname, provider, clients):
    """True when this login may relay mail that this provider will send."""
    if not provider or not (sasl_username or "").strip():
        return False
    provider_id = provider.get("id")
    user_id = provider.get("user_id")
    for client in clients:
        bound_to_provider = client.get("provider_id") == provider_id
        bound_to_user = client.get("provider_id") is None and client.get("user_id") == user_id
        if not bound_to_provider and not bound_to_user:
            continue
        if sasl_username_matches(sasl_username, client.get("smtp_username"), hostname):
            return True
    return False
