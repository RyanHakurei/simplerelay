"""Token format and Entra client-assertion checks. No network."""
import base64
import datetime
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.services.microsoft_oauth import (
    MicrosoftOAuthError,
    apply_hve_update,
    build_client_assertion,
    certificate_thumbprint,
    ensure_access_token,
    interpret_token_response,
    resolve_hve_on_create,
    start_device_flow,
    token_is_fresh,
    validate_certificate,
)
from backend.services.xoauth2_smtp import xoauth2_response


TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"


def _cert_and_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hve-test")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, key


class XOauth2Tests(unittest.TestCase):
    def test_sasl_initial_response(self):
        encoded = xoauth2_response("hve@contoso.com", "token-value")
        raw = base64.b64decode(encoded).decode()
        self.assertEqual(raw, "user=hve@contoso.com\x01auth=Bearer token-value\x01\x01")


class CertificateTests(unittest.TestCase):
    def test_assertion_uses_matching_thumbprint(self):
        cert_pem, key_pem, key = _cert_and_key()
        token = build_client_assertion(TENANT, CLIENT, cert_pem, key_pem)
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["x5t"], certificate_thumbprint(cert_pem))
        claims = jwt.decode(
            token,
            key.public_key(),
            algorithms=["RS256"],
            audience=f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        )
        self.assertEqual(claims["iss"], CLIENT)
        self.assertEqual(claims["sub"], CLIENT)

    def test_key_must_match_certificate(self):
        cert_pem, _, _ = _cert_and_key()
        _, other_key, _ = _cert_and_key()
        with self.assertRaises(MicrosoftOAuthError):
            validate_certificate(cert_pem, other_key)

    def test_combined_pem_with_bag_attributes(self):
        cert_pem, key_pem, _ = _cert_and_key()
        combined = "Bag Attributes\n    localKeyID: 01\n" + cert_pem + "\n" + key_pem
        cert_out, key_out = validate_certificate(combined, "")
        self.assertTrue(cert_out.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(key_out.startswith("-----BEGIN PRIVATE KEY-----"))

    def test_encrypted_key_rejected(self):
        cert_pem, key_pem, _ = _cert_and_key()
        encrypted = key_pem.replace("BEGIN PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY")
        encrypted = encrypted.replace("END PRIVATE KEY", "END ENCRYPTED PRIVATE KEY")
        with self.assertRaises(MicrosoftOAuthError) as caught:
            validate_certificate(cert_pem, encrypted)
        self.assertIn("encrypted", str(caught.exception).lower())


class TokenResponseTests(unittest.TestCase):
    def test_device_flow_accepts_verification_url(self):
        with patch("backend.services.microsoft_oauth.post_form", return_value={
            "device_code": "d",
            "user_code": "ABCD",
            "verification_url": "https://login.microsoft.com/device",
            "expires_in": 900,
            "interval": 5,
        }):
            flow = start_device_flow(TENANT, CLIENT)
        self.assertEqual(flow["user_code"], "ABCD")
        self.assertEqual(flow["verification_uri"], "https://login.microsoft.com/device")

    def test_device_code_payload_is_success(self):
        payload = interpret_token_response(200, {"device_code": "d", "user_code": "ABCD"})
        self.assertEqual(payload["user_code"], "ABCD")

    def test_authorization_pending_is_not_fatal(self):
        with self.assertRaises(MicrosoftOAuthError) as caught:
            interpret_token_response(400, {
                "error": "authorization_pending",
                "error_description": "still waiting",
            })
        self.assertFalse(caught.exception.permanent)
        self.assertFalse(caught.exception.invalidate)
        self.assertEqual(caught.exception.code, "authorization_pending")

    def test_invalid_grant_drops_refresh_token(self):
        with self.assertRaises(MicrosoftOAuthError) as caught:
            interpret_token_response(400, {
                "error": "invalid_grant",
                "error_description": "AADSTS70000: expired",
            })
        self.assertTrue(caught.exception.permanent)
        self.assertTrue(caught.exception.invalidate)


class EnsureTokenTests(unittest.TestCase):
    def test_fresh_token_skips_network(self):
        now = datetime.datetime.utcnow()
        material = {
            "access_token": "cached",
            "expires_at": now + timedelta(minutes=30),
            "mode": "delegated",
        }
        with patch("backend.services.microsoft_oauth.post_form") as post:
            token, updates = ensure_access_token(material, now=now)
        self.assertEqual(token, "cached")
        self.assertIsNone(updates)
        post.assert_not_called()

    def test_near_expiry_refreshes_with_certificate(self):
        cert_pem, key_pem, _ = _cert_and_key()
        now = datetime.datetime.utcnow()
        material = {
            "tenant_id": TENANT,
            "client_id": CLIENT,
            "credential": "certificate",
            "mode": "delegated",
            "certificate_pem": cert_pem,
            "private_key_pem": key_pem,
            "client_secret": "",
            "refresh_token": "refresh-1",
            "access_token": "old",
            "expires_at": now + timedelta(minutes=5),
        }

        def fake_post(url, data):
            self.assertIn(TENANT, url)
            self.assertEqual(data["grant_type"], "refresh_token")
            self.assertIn("scope", data)
            self.assertIn("client_assertion", data)
            self.assertNotIn("client_secret", data)
            return {"access_token": "new", "expires_in": 3600, "refresh_token": "refresh-2"}

        with patch("backend.services.microsoft_oauth.post_form", side_effect=fake_post):
            token, updates = ensure_access_token(material, now=now)
        self.assertEqual(token, "new")
        self.assertEqual(updates["refresh_token"], "refresh-2")

    def test_application_mode_uses_client_credentials(self):
        cert_pem, key_pem, _ = _cert_and_key()
        material = {
            "tenant_id": TENANT,
            "client_id": CLIENT,
            "credential": "certificate",
            "mode": "application",
            "certificate_pem": cert_pem,
            "private_key_pem": key_pem,
            "client_secret": "",
            "refresh_token": "",
            "access_token": "",
            "expires_at": None,
        }

        def fake_post(url, data):
            self.assertEqual(data["grant_type"], "client_credentials")
            self.assertEqual(data["scope"], "https://outlook.office.com/.default")
            self.assertIn("client_assertion", data)
            return {"access_token": "app-token", "expires_in": 3600}

        with patch("backend.services.microsoft_oauth.post_form", side_effect=fake_post):
            token, updates = ensure_access_token(material)
        self.assertEqual(token, "app-token")
        self.assertNotIn("refresh_token", updates)

    def test_delegated_without_refresh_asks_for_signin(self):
        material = {
            "tenant_id": TENANT,
            "client_id": CLIENT,
            "credential": "public",
            "mode": "delegated",
            "client_secret": "",
            "certificate_pem": "",
            "private_key_pem": "",
            "refresh_token": "",
            "access_token": "",
            "expires_at": None,
        }
        with self.assertRaises(MicrosoftOAuthError) as caught:
            ensure_access_token(material)
        self.assertEqual(caught.exception.code, "sign_in_required")
        self.assertFalse(caught.exception.permanent)


class ResolveTests(unittest.TestCase):
    def test_application_public_client_rejected(self):
        with self.assertRaises(MicrosoftOAuthError):
            resolve_hve_on_create(TENANT, CLIENT, "public", "application", None, None, None)

    def test_client_secret_is_rejected(self):
        with self.assertRaises(MicrosoftOAuthError):
            resolve_hve_on_create(TENANT, CLIENT, "secret", "delegated", "secret-value", None, None)

    def test_certificate_is_stored_encrypted(self):
        cert_pem, key_pem, _ = _cert_and_key()
        saved = resolve_hve_on_create(
            TENANT, CLIENT, "certificate", "delegated", None, cert_pem, key_pem,
        )
        self.assertEqual(saved["oauth_credential"], "certificate")
        self.assertEqual(saved["oauth_status"], "needs_signin")
        self.assertTrue(saved["oauth_cert_pem_encrypted"])
        self.assertTrue(saved["oauth_key_pem_encrypted"])
        self.assertIsNone(saved["oauth_client_secret_encrypted"])

    def test_update_switches_credential_to_certificate(self):
        cert_pem, key_pem, _ = _cert_and_key()
        provider = SimpleNamespace(
            oauth_tenant_id=TENANT,
            oauth_client_id=CLIENT,
            oauth_credential="public",
            oauth_mode="delegated",
            oauth_status="needs_signin",
            oauth_client_secret_encrypted=None,
            oauth_cert_pem_encrypted=None,
            oauth_key_pem_encrypted=None,
            oauth_refresh_token_encrypted="stale-refresh",
            oauth_access_token_encrypted="stale-access",
            oauth_token_expires_at=None,
            oauth_device_code_encrypted=None,
            oauth_device_expires_at=None,
            oauth_pkce_verifier_encrypted=None,
            oauth_user_code="ABCD",
            oauth_verification_uri="https://microsoft.com/devicelogin",
        )
        changed = apply_hve_update(provider, {
            "oauth_credential": "certificate",
            "certificate_pem": "Bag Attributes\n" + cert_pem,
            "private_key_pem": key_pem,
        })
        self.assertTrue(changed)
        self.assertEqual(provider.oauth_credential, "certificate")
        self.assertTrue(provider.oauth_cert_pem_encrypted)
        self.assertTrue(provider.oauth_key_pem_encrypted)
        self.assertIsNone(provider.oauth_client_secret_encrypted)
        self.assertIsNone(provider.oauth_refresh_token_encrypted)
        self.assertEqual(provider.oauth_status, "needs_signin")

    def test_token_freshness_window(self):
        now = datetime.datetime.utcnow()
        self.assertFalse(token_is_fresh("t", now + timedelta(minutes=9), now=now))
        self.assertTrue(token_is_fresh("t", now + timedelta(minutes=11), now=now))


if __name__ == "__main__":
    unittest.main()
