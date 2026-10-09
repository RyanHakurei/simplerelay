"""SASL XOAUTH2 for an already-connected smtplib session.

Microsoft's HVE SMTP exchange is:

    AUTH XOAUTH2 base64(user={mailbox}\\x01auth=Bearer {token}\\x01\\x01)

A failed token comes back as 334 with an error payload. The client must send
an empty line and then read the final 535.
"""
import base64
import smtplib


def xoauth2_response(username: str, access_token: str) -> str:
    raw = f"user={username}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def auth_xoauth2(smtp: smtplib.SMTP, username: str, access_token: str) -> None:
    code, resp = smtp.docmd("AUTH", "XOAUTH2 " + xoauth2_response(username, access_token))
    if code == 334:
        code, resp = smtp.docmd("")
    if code != 235:
        raise smtplib.SMTPAuthenticationError(code, resp)


def probe_xoauth2(host: str, port: int, tls_mode: str, username: str, access_token: str) -> None:
    """Connect, STARTTLS, and AUTH XOAUTH2. Raises on failure."""
    smtp = None
    try:
        if tls_mode == "ssl" or port == 465:
            smtp = smtplib.SMTP_SSL(host, port, timeout=20)
            smtp.ehlo()
        else:
            smtp = smtplib.SMTP(host, port, timeout=20)
            smtp.ehlo()
            if tls_mode != "none":
                smtp.starttls()
                smtp.ehlo()
        auth_xoauth2(smtp, username, access_token)
        smtp.quit()
        smtp = None
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass
